import { Types } from "mongoose";
import { Shipment, IShipment } from "../../shared/models/Shipment";
import { DeliveryType, ShipmentStatus, PaymentStatus } from "../../shared/lib/enums";

const PRICE_PER_KG = 500;

export interface CreateShipmentBody {
  deliveryType: "instant" | "scheduled";
  pickupWindowStart?: string;
  pickupWindowEnd?: string;
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
  async createShipment(userId: string, data: CreateShipmentBody): Promise<IShipment> {
    const initialStatus =
      data.deliveryType === DeliveryType.SCHEDULED ? ShipmentStatus.SCHEDULED : ShipmentStatus.PENDING;
    const price = Math.round(data.packageDetails.weight * PRICE_PER_KG);
    const createPayload: {
      userId: Types.ObjectId;
      status: string;
      deliveryType: string;
      riderID: null;
      price: number;
      paymentStatus: string;
      timeline: { status: string; timestamp: Date }[];
      senderDetails: typeof data.senderDetails;
      recipientDetails: typeof data.recipientDetails;
      packageDetails: { type: string; weight: number; dimensions: number; quantity: number; note: string };
      pickupWindowStart?: Date;
      pickupWindowEnd?: Date;
    } = {
      userId: new Types.ObjectId(userId),
      status: initialStatus,
      deliveryType: data.deliveryType,
      riderID: null,
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
    const shipment = await Shipment.create(createPayload);
    return shipment;
  }

  async findByUserId(userId: string): Promise<IShipment[]> {
    const list = await Shipment.find({ userId: new Types.ObjectId(userId) })
      .sort({ createdAt: -1 })
      .lean()
      .exec();
    return list as unknown as IShipment[];
  }
}
