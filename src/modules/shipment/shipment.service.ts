import { Types } from "mongoose";
import { Shipment, IShipment } from "../../shared/models/Shipment";
import { Rider } from "../../shared/models/Rider";
import { DeliveryType, ShipmentStatus, PaymentStatus, NotificationType } from "../../shared/lib/enums";
import { RiderService } from "../rider/rider.service";
import { NotificationService } from "../notification/notification.service";
import { logger } from "../../shared/lib/logger";

const PRICE_PER_KG = 500;
const RIDER_RESPONSE_WINDOW_MS = 3 * 60 * 1000;

function uniqueRiderObjectIds(ids: Types.ObjectId[]): Types.ObjectId[] {
  const seen = new Set<string>();
  const out: Types.ObjectId[] = [];
  for (const id of ids) {
    const s = id.toString();
    if (!seen.has(s)) {
      seen.add(s);
      out.push(id);
    }
  }
  return out;
}

export interface CreateShipmentBody {
  deliveryType: "instant" | "scheduled";
  pickupWindowStart?: string;
  pickupWindowEnd?: string;
  /** Pickup point for nearest-rider matching (WGS84). Required for instant delivery. */
  pickupLongitude?: number;
  pickupLatitude?: number;
  senderDetails: { fullName: string; address: string; phone: string };
  recipientDetails: { fullName: string; address: string; phone: string };
  packageDetails: {
    type: string;
    weight: number;
    dimensions: number;
    quantity: number;
    note?: string;
  };
}

export class ShipmentService {
  private riderService = new RiderService();
  private notificationService = new NotificationService();

  private async notifyRiderShipmentAssigned(riderMongoId: string, shipmentId: string): Promise<void> {
    try {
      const rider = await Rider.findById(riderMongoId).select("userId").lean();
      const uid = rider?.userId ? String(rider.userId) : null;
      if (!uid) return;
      await this.notificationService.createForUser(uid, {
        type: NotificationType.SHIPMENT_ASSIGNED,
        title: "New shipment assigned",
        message: "A shipment is waiting for your response. Open Active delivery to accept or decline.",
        relatedShipmentId: shipmentId,
      });
    } catch (e) {
      logger.error("Failed to notify rider of assignment", {
        message: e instanceof Error ? e.message : String(e),
      });
    }
  }

  private async notifyClientRiderAccepted(clientUserId: string, shipmentId: string): Promise<void> {
    try {
      await this.notificationService.createForUser(clientUserId, {
        type: NotificationType.RIDER_ACCEPTED_SHIPMENT,
        title: "Rider accepted your shipment",
        message: "A rider has accepted and will handle your delivery.",
        relatedShipmentId: shipmentId,
      });
    } catch (e) {
      logger.error("Failed to notify client of rider accept", {
        message: e instanceof Error ? e.message : String(e),
      });
    }
  }

  private async notifyClientDeliveryComplete(clientUserId: string, shipmentId: string): Promise<void> {
    try {
      await this.notificationService.createForUser(clientUserId, {
        type: NotificationType.DELIVERY_COMPLETE,
        title: "Delivery complete",
        message: "Your shipment has been marked as delivered.",
        relatedShipmentId: shipmentId,
      });
    } catch (e) {
      logger.error("Failed to notify client of delivery", {
        message: e instanceof Error ? e.message : String(e),
      });
    }
  }

  async createShipment(userId: string, data: CreateShipmentBody): Promise<IShipment> {
    let initialStatus =
      data.deliveryType === DeliveryType.SCHEDULED ? ShipmentStatus.SCHEDULED : ShipmentStatus.PENDING;
    const price = Math.round(data.packageDetails.weight * PRICE_PER_KG);

    let assignedRiderId: Types.ObjectId | null = null;
    if (data.deliveryType === DeliveryType.INSTANT) {
      const lng = data.pickupLongitude;
      const lat = data.pickupLatitude;
      if (lng === undefined || lat === undefined || Number.isNaN(lng) || Number.isNaN(lat)) {
        throw new Error("pickupLongitude and pickupLatitude are required for instant delivery.");
      }
      if (lng < -180 || lng > 180 || lat < -90 || lat > 90) {
        throw new Error("Invalid pickup coordinates.");
      }
      const rider = await this.riderService.claimNearestAvailableRider(lng, lat, []);
      if (!rider) {
        throw new Error("No rider available nearby.");
      }
      assignedRiderId = rider._id as Types.ObjectId;
      initialStatus = ShipmentStatus.AWAITING_RIDER_RESPONSE;
    }

    const createPayload: {
      userId: Types.ObjectId;
      status: string;
      deliveryType: string;
      riderID: Types.ObjectId | null;
      price: number;
      paymentStatus: string;
      timeline: { status: string; timestamp: Date }[];
      senderDetails: typeof data.senderDetails;
      recipientDetails: typeof data.recipientDetails;
      packageDetails: { type: string; weight: number; dimensions: number; quantity: number; note: string };
      pickupWindowStart?: Date;
      pickupWindowEnd?: Date;
      pickupLongitude?: number;
      pickupLatitude?: number;
      riderResponseDeadline?: Date;
      declinedRiderIds?: Types.ObjectId[];
    } = {
      userId: new Types.ObjectId(userId),
      status: initialStatus,
      deliveryType: data.deliveryType,
      riderID: assignedRiderId,
      price,
      paymentStatus: PaymentStatus.PENDING,
      timeline: [{ status: initialStatus, timestamp: new Date() }],
      senderDetails: data.senderDetails,
      recipientDetails: data.recipientDetails,
      packageDetails: {
        ...data.packageDetails,
        note: data.packageDetails.note ?? "",
      },
    };
    if (data.deliveryType === DeliveryType.INSTANT && data.pickupLongitude != null && data.pickupLatitude != null) {
      createPayload.pickupLongitude = data.pickupLongitude;
      createPayload.pickupLatitude = data.pickupLatitude;
      createPayload.riderResponseDeadline = new Date(Date.now() + RIDER_RESPONSE_WINDOW_MS);
      createPayload.declinedRiderIds = [];
    }
    if (data.deliveryType === DeliveryType.SCHEDULED && data.pickupWindowStart != null && data.pickupWindowEnd != null) {
      const start = new Date(data.pickupWindowStart);
      const now = new Date();

      const todayStartUTC = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 0, 0, 0, 0));
      const startDateUTC = new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth(), start.getUTCDate(), 0, 0, 0, 0));
      const maxDateUTC = new Date(todayStartUTC);
      maxDateUTC.setUTCDate(maxDateUTC.getUTCDate() + 7);

      if (startDateUTC.getTime() < todayStartUTC.getTime()) {
        throw new Error("Pickup date cannot be in the past.");
      }
      if (startDateUTC.getTime() > maxDateUTC.getTime()) {
        throw new Error("Pickup date cannot be more than 7 days ahead.");
      }
      const oneHourFromNow = now.getTime() + 60 * 60 * 1000;
      if (start.getTime() < oneHourFromNow) {
        throw new Error("Pickup must be at least 1 hour from now.");
      }

      createPayload.pickupWindowStart = start;
      createPayload.pickupWindowEnd = new Date(data.pickupWindowEnd);
    }
    try {
      const shipment = await Shipment.create(createPayload);
      if (assignedRiderId) {
        void this.notifyRiderShipmentAssigned(assignedRiderId.toString(), shipment._id.toString());
      }
      return shipment;
    } catch (err) {
      if (assignedRiderId) {
        await this.riderService.setRiderAvailable(assignedRiderId.toString(), true);
      }
      throw err;
    }
  }

  async markDelivered(shipmentId: string, authUserId: string, role: string): Promise<IShipment> {
    const shipment = await Shipment.findById(shipmentId).exec();
    if (!shipment) {
      throw new Error("Shipment not found");
    }
    if (shipment.status === ShipmentStatus.DELIVERED) {
      return shipment;
    }
    if (!shipment.riderID) {
      throw new Error("Shipment has no assigned rider");
    }
    const rider = await Rider.findById(shipment.riderID).exec();
    if (!rider) {
      throw new Error("Rider not found");
    }
    const riderUserId = rider.userId.toString();
    const isAssignedRider = riderUserId === authUserId;
    const isAdmin = role === "admin";
    if (!isAssignedRider && !isAdmin) {
      throw new Error("Not authorized to complete this shipment");
    }
    if (
      shipment.status !== ShipmentStatus.RIDER_ASSIGNED &&
      shipment.status !== ShipmentStatus.PICKED_UP &&
      shipment.status !== ShipmentStatus.IN_TRANSIT
    ) {
      throw new Error("Shipment cannot be marked delivered from its current status");
    }

    shipment.status = ShipmentStatus.DELIVERED;
    shipment.timeline.push({ status: ShipmentStatus.DELIVERED, timestamp: new Date() });
    await shipment.save();
    await this.riderService.setRiderAvailable(rider._id.toString(), true);
    void this.notifyClientDeliveryComplete(shipment.userId.toString(), shipment._id.toString());
    return shipment;
  }

  /**
   * Release current rider, record decline, offer to next nearest or set searching_rider.
   */
  async reassignAfterRiderPass(shipmentId: string): Promise<IShipment | null> {
    const shipment = await Shipment.findById(shipmentId).exec();
    if (!shipment || shipment.status !== ShipmentStatus.AWAITING_RIDER_RESPONSE || !shipment.riderID) {
      return shipment;
    }

    const currentId = shipment.riderID as Types.ObjectId;
    await this.riderService.setRiderAvailable(currentId.toString(), true);

    const previousDeclined = (shipment.declinedRiderIds || []).map((id) =>
      id instanceof Types.ObjectId ? id : new Types.ObjectId(String(id))
    );
    const excludeIds = uniqueRiderObjectIds([...previousDeclined, currentId]);
    shipment.declinedRiderIds = excludeIds;

    const lng = shipment.pickupLongitude;
    const lat = shipment.pickupLatitude;

    if (lng === undefined || lat === undefined || Number.isNaN(lng) || Number.isNaN(lat)) {
      shipment.riderID = null;
      shipment.status = ShipmentStatus.SEARCHING_RIDER;
      shipment.riderResponseDeadline = undefined;
      shipment.timeline.push({ status: ShipmentStatus.SEARCHING_RIDER, timestamp: new Date() });
      await shipment.save();
      return shipment;
    }

    const nextRider = await this.riderService.claimNearestAvailableRider(lng, lat, excludeIds);
    if (!nextRider) {
      shipment.riderID = null;
      shipment.status = ShipmentStatus.SEARCHING_RIDER;
      shipment.riderResponseDeadline = undefined;
      shipment.timeline.push({ status: ShipmentStatus.SEARCHING_RIDER, timestamp: new Date() });
      await shipment.save();
      return shipment;
    }

    shipment.riderID = nextRider._id as Types.ObjectId;
    shipment.status = ShipmentStatus.AWAITING_RIDER_RESPONSE;
    shipment.riderResponseDeadline = new Date(Date.now() + RIDER_RESPONSE_WINDOW_MS);
    shipment.timeline.push({ status: ShipmentStatus.AWAITING_RIDER_RESPONSE, timestamp: new Date() });
    await shipment.save();
    void this.notifyRiderShipmentAssigned(nextRider._id.toString(), shipment._id.toString());
    return shipment;
  }

  async processExpiredRiderOffers(): Promise<void> {
    const now = new Date();
    const expired = await Shipment.find({
      status: ShipmentStatus.AWAITING_RIDER_RESPONSE,
      riderResponseDeadline: { $lt: now },
    })
      .select("_id")
      .lean()
      .exec();
    for (const row of expired) {
      try {
        await this.reassignAfterRiderPass(row._id.toString());
      } catch (err) {
        logger.error("Failed to expire rider offer", {
          shipmentId: row._id?.toString(),
          message: err instanceof Error ? err.message : String(err),
        });
      }
    }
  }

  private async loadShipmentForRiderResponse(
    shipmentId: string,
    authUserId: string,
    role: string
  ): Promise<{ shipment: IShipment }> {
    if (role !== "rider") {
      throw new Error("Rider access required");
    }
    const shipment = await Shipment.findById(shipmentId).exec();
    if (!shipment) {
      throw new Error("Shipment not found");
    }
    if (shipment.status !== ShipmentStatus.AWAITING_RIDER_RESPONSE || !shipment.riderID) {
      throw new Error("This shipment is not awaiting your response");
    }
    const rider = await Rider.findById(shipment.riderID).exec();
    if (!rider || rider.userId.toString() !== authUserId) {
      throw new Error("Not authorized to respond to this offer");
    }
    return { shipment };
  }

  async acceptRiderOffer(shipmentId: string, authUserId: string, role: string): Promise<IShipment> {
    await this.processExpiredRiderOffers();
    const { shipment } = await this.loadShipmentForRiderResponse(shipmentId, authUserId, role);
    const now = new Date();
    if (!shipment.riderResponseDeadline || now > shipment.riderResponseDeadline) {
      throw new Error("This offer has expired");
    }
    shipment.status = ShipmentStatus.RIDER_ASSIGNED;
    shipment.riderResponseDeadline = undefined;
    shipment.timeline.push({ status: ShipmentStatus.RIDER_ASSIGNED, timestamp: new Date() });
    await shipment.save();
    void this.notifyClientRiderAccepted(shipment.userId.toString(), shipment._id.toString());
    return shipment;
  }

  async rejectRiderOffer(shipmentId: string, authUserId: string, role: string): Promise<IShipment> {
    await this.processExpiredRiderOffers();
    const { shipment } = await this.loadShipmentForRiderResponse(shipmentId, authUserId, role);
    const now = new Date();
    if (!shipment.riderResponseDeadline || now > shipment.riderResponseDeadline) {
      throw new Error("This offer has expired");
    }
    const updated = await this.reassignAfterRiderPass(shipment._id.toString());
    if (!updated) {
      throw new Error("Shipment not found");
    }
    return updated;
  }

  async findByUserId(userId: string): Promise<IShipment[]> {
    const list = await Shipment.find({ userId: new Types.ObjectId(userId) })
      .sort({ createdAt: -1 })
      .lean()
      .exec();
    return list as unknown as IShipment[];
  }

  /**
   * Shipments assigned to the rider linked to this auth user (User._id).
   * @param scope active = in progress; history = delivered or cancelled; all = any assigned to rider
   */
  async findShipmentsForRiderUser(
    authUserId: string,
    scope: "active" | "history" | "all"
  ): Promise<IShipment[] | null> {
    await this.processExpiredRiderOffers();
    const rider = await this.riderService.findByUserId(authUserId);
    if (!rider) {
      return null;
    }
    const riderObjectId = rider._id as Types.ObjectId;
    const base = { riderID: riderObjectId };

    if (scope === "active") {
      const list = await Shipment.find({
        ...base,
        status: {
          $in: [
            ShipmentStatus.AWAITING_RIDER_RESPONSE,
            ShipmentStatus.RIDER_ASSIGNED,
            ShipmentStatus.PICKED_UP,
            ShipmentStatus.IN_TRANSIT,
          ],
        },
      })
        .sort({ updatedAt: -1 })
        .lean()
        .exec();
      return list as unknown as IShipment[];
    }

    if (scope === "history") {
      const list = await Shipment.find({
        ...base,
        status: { $in: [ShipmentStatus.DELIVERED, ShipmentStatus.CANCELLED] },
      })
        .sort({ createdAt: -1 })
        .lean()
        .exec();
      return list as unknown as IShipment[];
    }

    const list = await Shipment.find(base).sort({ createdAt: -1 }).lean().exec();
    return list as unknown as IShipment[];
  }
}
