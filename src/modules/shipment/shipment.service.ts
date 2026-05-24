import { Types } from "mongoose";
import { Shipment, IShipment } from "../../shared/models/Shipment";
import { Rider } from "../../shared/models/Rider";
import {
  DeliveryType,
  ShipmentStatus,
  PaymentStatus,
  NotificationType,
  UserAccountStatus,
} from "../../shared/lib/enums";
import { User } from "../../shared/models/User";
import { RiderService } from "../rider/rider.service";
import { NotificationService } from "../notification/notification.service";
import { logger } from "../../shared/lib/logger";
import { normalizeContactDetails, type ContactDetailsInput } from "../../shared/lib/nigeria-locations";
import {
  computeShipmentPrice,
  formatContactAddress,
  parsePackageDimensions,
  type ShipmentPriceBreakdown,
} from "../../shared/lib/shipment-pricing";
import { drivingDistanceMeters, geocodeAddress } from "../../shared/lib/google-maps.service";
import {
  generatePaymentReference,
  getPaystackPublicKey,
  initializeTransaction,
  verifyTransaction,
} from "../../shared/lib/paystack.service";

export type { ShipmentPriceBreakdown };
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
  senderDetails: ContactDetailsInput;
  recipientDetails: ContactDetailsInput;
  packageDetails: {
    type: string;
    weight: number;
    lengthCm: number;
    widthCm: number;
    heightCm: number;
    quantity: number;
    note?: string;
  };
  /** Optional drop-off coordinates for maps. */
  recipientLongitude?: number;
  recipientLatitude?: number;
}

export interface EstimateShipmentPriceBody {
  senderDetails: ContactDetailsInput;
  recipientDetails: ContactDetailsInput;
  weight: number;
  lengthCm: number;
  widthCm: number;
  heightCm: number;
}

export interface ShipmentTrackingDto {
  shipmentId: string;
  status: string;
  pickup: { longitude: number; latitude: number } | null;
  recipient: { longitude: number; latitude: number } | null;
  rider: { longitude: number; latitude: number } | null;
  riderLocationUpdatedAt: string | null;
}

/** Deduped contact row for riders (pickup vs drop-off) from assigned shipments. */
export interface RiderAddressBookEntry {
  role: "sender" | "recipient";
  fullName: string;
  address: string;
  phone: string;
  lastSeenAt: string;
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

  async estimateShipmentPrice(data: EstimateShipmentPriceBody): Promise<ShipmentPriceBreakdown> {
    const senderDetails = normalizeContactDetails(data.senderDetails, "Sender");
    const recipientDetails = normalizeContactDetails(data.recipientDetails, "Recipient");
    const weightKg = Number(data.weight);
    if (!Number.isFinite(weightKg) || weightKg < 0) {
      throw new Error("weight must be a non-negative number");
    }
    const dims = parsePackageDimensions(data.lengthCm, data.widthCm, data.heightCm);

    const origin = await geocodeAddress(formatContactAddress(senderDetails));
    const destination = await geocodeAddress(formatContactAddress(recipientDetails));
    const distanceMeters = await drivingDistanceMeters(origin, destination);
    return computeShipmentPrice(
      distanceMeters,
      weightKg,
      dims.lengthCm,
      dims.widthCm,
      dims.heightCm
    );
  }

  async resolveShipmentPrice(
    senderDetails: { address: string; state: string; country: string },
    recipientDetails: { address: string; state: string; country: string },
    weightKg: number,
    lengthCm: number,
    widthCm: number,
    heightCm: number
  ): Promise<number> {
    const origin = await geocodeAddress(formatContactAddress(senderDetails));
    const destination = await geocodeAddress(formatContactAddress(recipientDetails));
    const distanceMeters = await drivingDistanceMeters(origin, destination);
    return computeShipmentPrice(distanceMeters, weightKg, lengthCm, widthCm, heightCm).total;
  }

  async createShipment(userId: string, data: CreateShipmentBody): Promise<IShipment> {
    const clientUser = await User.findById(userId).select("status role").lean().exec();
    if (!clientUser) {
      throw new Error("User not found");
    }
    if (clientUser.role === "client") {
      const status = clientUser.status || UserAccountStatus.ACTIVE;
      if (status !== UserAccountStatus.ACTIVE) {
        throw new Error("Your account cannot create shipments. Contact support for assistance.");
      }
    }

    const senderDetails = normalizeContactDetails(data.senderDetails, "Sender");
    const recipientDetails = normalizeContactDetails(data.recipientDetails, "Recipient");

    let initialStatus =
      data.deliveryType === DeliveryType.SCHEDULED ? ShipmentStatus.SCHEDULED : ShipmentStatus.PENDING;
    const price = await this.resolveShipmentPrice(
      senderDetails,
      recipientDetails,
      data.packageDetails.weight,
      data.packageDetails.lengthCm,
      data.packageDetails.widthCm,
      data.packageDetails.heightCm
    );

    if (data.deliveryType === DeliveryType.INSTANT) {
      const lng = data.pickupLongitude;
      const lat = data.pickupLatitude;
      if (lng === undefined || lat === undefined || Number.isNaN(lng) || Number.isNaN(lat)) {
        throw new Error("pickupLongitude and pickupLatitude are required for instant delivery.");
      }
      if (lng < -180 || lng > 180 || lat < -90 || lat > 90) {
        throw new Error("Invalid pickup coordinates.");
      }
    }

    const createPayload: {
      userId: Types.ObjectId;
      status: string;
      deliveryType: string;
      riderID: Types.ObjectId | null;
      price: number;
      paymentStatus: string;
      timeline: { status: string; timestamp: Date }[];
      senderDetails: typeof senderDetails;
      recipientDetails: typeof recipientDetails;
      packageDetails: {
        type: string;
        weight: number;
        lengthCm: number;
        widthCm: number;
        heightCm: number;
        quantity: number;
        note: string;
      };
      pickupWindowStart?: Date;
      pickupWindowEnd?: Date;
      pickupLongitude?: number;
      pickupLatitude?: number;
      recipientLongitude?: number;
      recipientLatitude?: number;
      riderResponseDeadline?: Date;
      declinedRiderIds?: Types.ObjectId[];
    } = {
      userId: new Types.ObjectId(userId),
      status: initialStatus,
      deliveryType: data.deliveryType,
      riderID: null,
      price,
      paymentStatus: PaymentStatus.PENDING,
      timeline: [{ status: initialStatus, timestamp: new Date() }],
      senderDetails,
      recipientDetails,
      packageDetails: {
        ...data.packageDetails,
        note: data.packageDetails.note ?? "",
      },
    };
    if (data.deliveryType === DeliveryType.INSTANT && data.pickupLongitude != null && data.pickupLatitude != null) {
      createPayload.pickupLongitude = data.pickupLongitude;
      createPayload.pickupLatitude = data.pickupLatitude;
      createPayload.declinedRiderIds = [];
    }
    const recLng = data.recipientLongitude;
    const recLat = data.recipientLatitude;
    const hasRecLng = recLng !== undefined && recLng !== null && !Number.isNaN(Number(recLng));
    const hasRecLat = recLat !== undefined && recLat !== null && !Number.isNaN(Number(recLat));
    if (hasRecLng !== hasRecLat) {
      throw new Error("recipientLongitude and recipientLatitude must both be provided together.");
    }
    if (hasRecLng && hasRecLat) {
      const rl = Number(recLng);
      const ra = Number(recLat);
      if (rl < -180 || rl > 180 || ra < -90 || ra > 90) {
        throw new Error("Invalid recipient coordinates.");
      }
      createPayload.recipientLongitude = rl;
      createPayload.recipientLatitude = ra;
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
    return Shipment.create(createPayload);
  }

  /**
   * Admin creates a shipment on behalf of a client without auto nearest-rider matching.
   * Rider assignment is done separately via adminAssignRider.
   */
  async createShipmentForAdmin(clientUserId: string, data: CreateShipmentBody): Promise<IShipment> {
    const clientUser = await User.findById(clientUserId).select("status role").lean().exec();
    if (!clientUser) {
      throw new Error("Client not found");
    }
    if (clientUser.role !== "client") {
      throw new Error("Selected user is not a client");
    }
    const accountStatus = clientUser.status || UserAccountStatus.ACTIVE;
    if (accountStatus !== UserAccountStatus.ACTIVE) {
      throw new Error("This client account cannot create shipments.");
    }

    const senderDetails = normalizeContactDetails(data.senderDetails, "Sender");
    const recipientDetails = normalizeContactDetails(data.recipientDetails, "Recipient");

    const initialStatus =
      data.deliveryType === DeliveryType.SCHEDULED ? ShipmentStatus.SCHEDULED : ShipmentStatus.PENDING;
    const price = await this.resolveShipmentPrice(
      senderDetails,
      recipientDetails,
      data.packageDetails.weight,
      data.packageDetails.lengthCm,
      data.packageDetails.widthCm,
      data.packageDetails.heightCm
    );

    if (data.deliveryType === DeliveryType.INSTANT) {
      const lng = data.pickupLongitude;
      const lat = data.pickupLatitude;
      if (lng === undefined || lat === undefined || Number.isNaN(lng) || Number.isNaN(lat)) {
        throw new Error("pickupLongitude and pickupLatitude are required for instant delivery.");
      }
      if (lng < -180 || lng > 180 || lat < -90 || lat > 90) {
        throw new Error("Invalid pickup coordinates.");
      }
    }

    const createPayload: {
      userId: Types.ObjectId;
      status: string;
      deliveryType: string;
      riderID: Types.ObjectId | null;
      price: number;
      paymentStatus: string;
      paidAt: Date;
      timeline: { status: string; timestamp: Date }[];
      senderDetails: typeof senderDetails;
      recipientDetails: typeof recipientDetails;
      packageDetails: {
        type: string;
        weight: number;
        lengthCm: number;
        widthCm: number;
        heightCm: number;
        quantity: number;
        note: string;
      };
      pickupWindowStart?: Date;
      pickupWindowEnd?: Date;
      pickupLongitude?: number;
      pickupLatitude?: number;
      recipientLongitude?: number;
      recipientLatitude?: number;
    } = {
      userId: new Types.ObjectId(clientUserId),
      status: initialStatus,
      deliveryType: data.deliveryType,
      riderID: null,
      price,
      paymentStatus: PaymentStatus.PAID,
      paidAt: new Date(),
      timeline: [{ status: initialStatus, timestamp: new Date() }],
      senderDetails,
      recipientDetails,
      packageDetails: {
        ...data.packageDetails,
        note: data.packageDetails.note ?? "",
      },
    };

    if (data.deliveryType === DeliveryType.INSTANT && data.pickupLongitude != null && data.pickupLatitude != null) {
      createPayload.pickupLongitude = data.pickupLongitude;
      createPayload.pickupLatitude = data.pickupLatitude;
    }

    const recLng = data.recipientLongitude;
    const recLat = data.recipientLatitude;
    const hasRecLng = recLng !== undefined && recLng !== null && !Number.isNaN(Number(recLng));
    const hasRecLat = recLat !== undefined && recLat !== null && !Number.isNaN(Number(recLat));
    if (hasRecLng !== hasRecLat) {
      throw new Error("recipientLongitude and recipientLatitude must both be provided together.");
    }
    if (hasRecLng && hasRecLat) {
      const rl = Number(recLng);
      const ra = Number(recLat);
      if (rl < -180 || rl > 180 || ra < -90 || ra > 90) {
        throw new Error("Invalid recipient coordinates.");
      }
      createPayload.recipientLongitude = rl;
      createPayload.recipientLatitude = ra;
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

    return Shipment.create(createPayload);
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

  /**
   * Sender and recipient addresses from every shipment assigned to this rider (deduped by role + normalized address).
   */
  async findAddressBookForRiderUser(authUserId: string): Promise<RiderAddressBookEntry[] | null> {
    await this.processExpiredRiderOffers();
    const rider = await this.riderService.findByUserId(authUserId);
    if (!rider) {
      return null;
    }
    const riderObjectId = rider._id as Types.ObjectId;
    const rows = await Shipment.find({ riderID: riderObjectId })
      .select("senderDetails recipientDetails updatedAt createdAt")
      .sort({ updatedAt: -1 })
      .lean()
      .exec();

    const normalizeKey = (address: string) => address.trim().replace(/\s+/g, " ").toLowerCase();

    type Acc = RiderAddressBookEntry & { _ts: number };
    const byKey = new Map<string, Acc>();

    const upsert = (
      role: "sender" | "recipient",
      fullName: string,
      address: string,
      phone: string,
      ts: Date
    ) => {
      const key = `${role}:${normalizeKey(address)}`;
      const t = ts.getTime();
      const prev = byKey.get(key);
      if (!prev || t >= prev._ts) {
        byKey.set(key, {
          role,
          fullName: fullName.trim(),
          address: address.trim(),
          phone: phone.trim(),
          lastSeenAt: ts.toISOString(),
          _ts: t,
        });
      }
    };

    for (const row of rows) {
      const raw = (row as { updatedAt?: Date; createdAt?: Date }).updatedAt ?? (row as { createdAt?: Date }).createdAt;
      const ts = raw ? new Date(raw) : new Date();
      const s = (row as { senderDetails?: { fullName: string; address: string; phone: string } }).senderDetails;
      const r = (row as { recipientDetails?: { fullName: string; address: string; phone: string } }).recipientDetails;
      if (s?.address) upsert("sender", s.fullName ?? "", s.address, s.phone ?? "", ts);
      if (r?.address) upsert("recipient", r.fullName ?? "", r.address, r.phone ?? "", ts);
    }

    return Array.from(byKey.values())
      .map((v) => {
        const { _ts, ...entry } = v;
        return entry;
      })
      .sort((a, b) => new Date(b.lastSeenAt).getTime() - new Date(a.lastSeenAt).getTime());
  }

  async getTrackingForOwner(shipmentId: string, ownerUserId: string): Promise<ShipmentTrackingDto | null> {
    const shipment = await Shipment.findById(shipmentId).lean().exec();
    if (!shipment) {
      return null;
    }
    if (shipment.userId.toString() !== ownerUserId) {
      throw new Error("Not authorized to view tracking for this shipment");
    }

    let riderPoint: { longitude: number; latitude: number } | null = null;
    let riderLocationUpdatedAt: string | null = null;
    if (shipment.riderID) {
      const assigned = await Rider.findById(shipment.riderID).select("location updatedAt").lean().exec();
      const coords = assigned?.location?.coordinates;
      if (coords && coords.length >= 2 && typeof coords[0] === "number" && typeof coords[1] === "number") {
        riderPoint = { longitude: coords[0], latitude: coords[1] };
        riderLocationUpdatedAt = assigned?.updatedAt ? new Date(assigned.updatedAt).toISOString() : null;
      }
    }

    const pickup =
      shipment.pickupLongitude != null &&
      shipment.pickupLatitude != null &&
      !Number.isNaN(shipment.pickupLongitude) &&
      !Number.isNaN(shipment.pickupLatitude)
        ? { longitude: shipment.pickupLongitude, latitude: shipment.pickupLatitude }
        : null;

    const recipient =
      shipment.recipientLongitude != null &&
      shipment.recipientLatitude != null &&
      !Number.isNaN(shipment.recipientLongitude) &&
      !Number.isNaN(shipment.recipientLatitude)
        ? { longitude: shipment.recipientLongitude, latitude: shipment.recipientLatitude }
        : null;

    return {
      shipmentId: String(shipment._id),
      status: shipment.status,
      pickup,
      recipient,
      rider: riderPoint,
      riderLocationUpdatedAt,
    };
  }

  private async assertAssignedRiderUser(shipmentId: string, authUserId: string): Promise<IShipment> {
    const shipment = await Shipment.findById(shipmentId).exec();
    if (!shipment) {
      throw new Error("Shipment not found");
    }
    if (!shipment.riderID) {
      throw new Error("Shipment has no assigned rider");
    }
    const rider = await Rider.findById(shipment.riderID).exec();
    if (!rider || rider.userId.toString() !== authUserId) {
      throw new Error("Not authorized for this shipment");
    }
    return shipment;
  }

  async markPickedUp(shipmentId: string, authUserId: string, role: string): Promise<IShipment> {
    if (role !== "rider") {
      throw new Error("Rider access required");
    }
    const shipment = await this.assertAssignedRiderUser(shipmentId, authUserId);
    if (shipment.status !== ShipmentStatus.RIDER_ASSIGNED) {
      throw new Error("Shipment is not ready to be marked picked up");
    }
    shipment.status = ShipmentStatus.PICKED_UP;
    shipment.timeline.push({ status: ShipmentStatus.PICKED_UP, timestamp: new Date() });
    await shipment.save();
    return shipment;
  }

  async markInTransit(shipmentId: string, authUserId: string, role: string): Promise<IShipment> {
    if (role !== "rider") {
      throw new Error("Rider access required");
    }
    const shipment = await this.assertAssignedRiderUser(shipmentId, authUserId);
    if (shipment.status !== ShipmentStatus.PICKED_UP) {
      throw new Error("Shipment must be picked up before marking in transit");
    }
    shipment.status = ShipmentStatus.IN_TRANSIT;
    shipment.timeline.push({ status: ShipmentStatus.IN_TRANSIT, timestamp: new Date() });
    await shipment.save();
    return shipment;
  }

  private static readonly ADMIN_ASSIGNABLE_STATUSES: string[] = [
    ShipmentStatus.PENDING,
    ShipmentStatus.SCHEDULED,
    ShipmentStatus.SEARCHING_RIDER,
    ShipmentStatus.AWAITING_RIDER_RESPONSE,
  ];

  /**
   * Admin assigns an available rider; rider must accept the offer (same flow as instant auto-match).
   */
  async adminAssignRider(shipmentId: string, riderId: string): Promise<IShipment> {
    const shipment = await Shipment.findById(shipmentId).exec();
    if (!shipment) {
      throw new Error("Shipment not found");
    }
    if (!ShipmentService.ADMIN_ASSIGNABLE_STATUSES.includes(shipment.status)) {
      throw new Error("This shipment cannot be assigned in its current status");
    }

    if (shipment.status === ShipmentStatus.AWAITING_RIDER_RESPONSE && shipment.riderID) {
      await this.riderService.setRiderAvailable(shipment.riderID.toString(), true);
    }

    const claimed = await this.riderService.claimRiderById(riderId);
    if (!claimed) {
      throw new Error("Rider is not available or does not meet assignment requirements");
    }

    try {
      shipment.riderID = claimed._id as Types.ObjectId;
      shipment.status = ShipmentStatus.AWAITING_RIDER_RESPONSE;
      shipment.riderResponseDeadline = new Date(Date.now() + RIDER_RESPONSE_WINDOW_MS);
      if (!shipment.declinedRiderIds?.length) {
        shipment.declinedRiderIds = shipment.declinedRiderIds ?? [];
      }
      shipment.timeline.push({
        status: ShipmentStatus.AWAITING_RIDER_RESPONSE,
        timestamp: new Date(),
      });
      await shipment.save();
      void this.notifyRiderShipmentAssigned(claimed._id.toString(), shipment._id.toString());
      return shipment;
    } catch (err) {
      await this.riderService.setRiderAvailable(riderId, true);
      throw err;
    }
  }

  private async getShipmentForClient(shipmentId: string, userId: string): Promise<IShipment> {
    const shipment = await Shipment.findById(shipmentId).exec();
    if (!shipment) {
      throw new Error("Shipment not found");
    }
    if (shipment.userId.toString() !== userId) {
      throw new Error("Not authorized to access this shipment");
    }
    return shipment;
  }

  private expectedAmountKobo(priceNgn: number): number {
    return Math.round(priceNgn * 100);
  }

  async initializeShipmentPayment(
    shipmentId: string,
    userId: string
  ): Promise<{
    accessCode: string;
    reference: string;
    amountKobo: number;
    publicKey: string;
    email: string;
    alreadyPaid?: boolean;
  }> {
    const shipment = await this.getShipmentForClient(shipmentId, userId);
    if (shipment.paymentStatus === PaymentStatus.PAID) {
      throw new Error("Shipment is already paid");
    }

    const user = await User.findById(userId).select("email").lean().exec();
    if (!user?.email) {
      throw new Error("User email is required for payment");
    }

    const email = user.email.trim();
    const amountKobo = this.expectedAmountKobo(shipment.price);
    if (amountKobo < 1) {
      throw new Error("Invalid shipment amount for payment");
    }

    if (shipment.paystackReference) {
      try {
        const prior = await verifyTransaction(shipment.paystackReference);
        if (prior.status === "success" && prior.amountKobo === amountKobo) {
          await this.markShipmentPaidAndFulfill(shipment._id.toString(), shipment.paystackReference);
          return {
            accessCode: "",
            reference: shipment.paystackReference,
            amountKobo,
            publicKey: getPaystackPublicKey(),
            email,
            alreadyPaid: true,
          };
        }
      } catch (e) {
        logger.info("Prior Paystack reference not completed; starting new payment session", {
          reference: shipment.paystackReference,
          message: e instanceof Error ? e.message : String(e),
        });
      }
    }

    const reference = generatePaymentReference(shipment._id.toString());
    const init = await initializeTransaction({
      email,
      amountKobo,
      reference,
      metadata: {
        shipmentId: shipment._id.toString(),
        userId,
      },
    });

    shipment.paystackReference = init.reference;
    await shipment.save();

    return {
      accessCode: init.accessCode,
      reference: init.reference,
      amountKobo,
      publicKey: getPaystackPublicKey(),
      email,
    };
  }

  async verifyShipmentPayment(shipmentId: string, userId: string, reference: string): Promise<IShipment> {
    const shipment = await this.getShipmentForClient(shipmentId, userId);
    if (!reference?.trim()) {
      throw new Error("Payment reference is required");
    }
    if (shipment.paymentStatus === PaymentStatus.PAID) {
      return shipment;
    }

    const verified = await verifyTransaction(reference);
    if (verified.status !== "success") {
      shipment.paymentStatus = PaymentStatus.FAILED;
      await shipment.save();
      throw new Error("Payment was not successful");
    }

    const expectedKobo = this.expectedAmountKobo(shipment.price);
    if (verified.amountKobo !== expectedKobo) {
      throw new Error("Payment amount does not match shipment price");
    }

    return this.markShipmentPaidAndFulfill(shipment._id.toString(), reference);
  }

  async markShipmentPaidAndFulfill(shipmentId: string, reference?: string): Promise<IShipment> {
    const shipment = await Shipment.findById(shipmentId).exec();
    if (!shipment) {
      throw new Error("Shipment not found");
    }

    if (shipment.paymentStatus === PaymentStatus.PAID) {
      if (shipment.deliveryType === DeliveryType.INSTANT && !shipment.riderID) {
        await this.assignNearestRiderForInstant(shipment);
        return (await Shipment.findById(shipmentId).exec()) as IShipment;
      }
      return shipment;
    }

    shipment.paymentStatus = PaymentStatus.PAID;
    shipment.paidAt = new Date();
    if (reference) {
      shipment.paystackReference = reference;
    }
    await shipment.save();

    if (shipment.deliveryType === DeliveryType.INSTANT) {
      await this.assignNearestRiderForInstant(shipment);
      const updated = await Shipment.findById(shipmentId).exec();
      return updated ?? shipment;
    }

    return shipment;
  }

  private async assignNearestRiderForInstant(shipment: IShipment): Promise<void> {
    if (shipment.deliveryType !== DeliveryType.INSTANT) return;
    if (shipment.riderID) return;

    const lng = shipment.pickupLongitude;
    const lat = shipment.pickupLatitude;
    if (lng === undefined || lat === undefined || Number.isNaN(lng) || Number.isNaN(lat)) {
      throw new Error("Pickup coordinates are required to assign a rider");
    }

    const declined = shipment.declinedRiderIds ?? [];
    const rider = await this.riderService.claimNearestAvailableRider(lng, lat, declined);
    if (!rider) {
      throw new Error("No rider available nearby. Please try again later.");
    }

    const riderId = rider._id as Types.ObjectId;
    try {
      shipment.riderID = riderId;
      shipment.status = ShipmentStatus.AWAITING_RIDER_RESPONSE;
      shipment.riderResponseDeadline = new Date(Date.now() + RIDER_RESPONSE_WINDOW_MS);
      shipment.declinedRiderIds = declined;
      shipment.timeline.push({
        status: ShipmentStatus.AWAITING_RIDER_RESPONSE,
        timestamp: new Date(),
      });
      await shipment.save();
      void this.notifyRiderShipmentAssigned(riderId.toString(), shipment._id.toString());
    } catch (err) {
      await this.riderService.setRiderAvailable(riderId.toString(), true);
      throw err;
    }
  }

  async handlePaystackWebhook(event: {
    event?: string;
    data?: {
      reference?: string;
      amount?: number;
      metadata?: { shipmentId?: string; userId?: string };
    };
  }): Promise<void> {
    if (event.event !== "charge.success" || !event.data?.reference) {
      return;
    }

    const reference = event.data.reference;
    let shipment =
      (await Shipment.findOne({ paystackReference: reference }).exec()) ??
      (event.data.metadata?.shipmentId
        ? await Shipment.findById(event.data.metadata.shipmentId).exec()
        : null);

    if (!shipment) {
      logger.warn("Paystack webhook: shipment not found for reference", { reference });
      return;
    }

    if (shipment.paymentStatus === PaymentStatus.PAID) {
      return;
    }

    const expectedKobo = this.expectedAmountKobo(shipment.price);
    if (event.data.amount != null && event.data.amount !== expectedKobo) {
      logger.error("Paystack webhook: amount mismatch", {
        reference,
        expectedKobo,
        received: event.data.amount,
      });
      return;
    }

    await this.markShipmentPaidAndFulfill(shipment._id.toString(), reference);
  }
}
