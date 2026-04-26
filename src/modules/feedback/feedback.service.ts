import { Types } from "mongoose";
import { Feedback, IFeedback } from "../../shared/models/Feedback";
import { Shipment } from "../../shared/models/Shipment";
import { ShipmentStatus } from "../../shared/lib/enums";
import { Rider } from "../../shared/models/Rider";
import { User } from "../../shared/models/User";

export interface FeedbackDto {
  _id: string;
  clientUserId: string;
  riderId: string;
  shipmentId: string;
  rating: number;
  comment: string;
  riderName: string;
  createdAt: string;
  updatedAt: string;
}

function toDto(doc: IFeedback, riderName = "Rider"): FeedbackDto {
  return {
    _id: doc._id.toString(),
    clientUserId: doc.clientUserId.toString(),
    riderId: doc.riderId.toString(),
    shipmentId: doc.shipmentId.toString(),
    rating: doc.rating,
    comment: doc.comment ?? "",
    riderName,
    createdAt: doc.createdAt.toISOString(),
    updatedAt: doc.updatedAt.toISOString(),
  };
}

export class FeedbackService {
  async createForDeliveredShipment(params: {
    clientUserId: string;
    shipmentId: string;
    rating: number;
    comment?: string;
  }): Promise<FeedbackDto> {
    const { clientUserId, shipmentId, rating } = params;
    const comment = (params.comment ?? "").trim();

    if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
      throw new Error("rating must be an integer between 1 and 5");
    }

    const shipment = await Shipment.findById(shipmentId).exec();
    if (!shipment) {
      throw new Error("Shipment not found");
    }
    if (shipment.userId.toString() !== clientUserId) {
      throw new Error("Not authorized to leave feedback for this shipment");
    }
    if (shipment.status !== ShipmentStatus.DELIVERED) {
      throw new Error("Feedback can only be left for delivered shipments");
    }
    if (!shipment.riderID) {
      throw new Error("Shipment has no rider to review");
    }

    const existing = await Feedback.findOne({
      shipmentId: new Types.ObjectId(shipmentId),
      clientUserId: new Types.ObjectId(clientUserId),
    }).exec();
    if (existing) {
      throw new Error("Feedback already submitted for this shipment");
    }

    const created = await Feedback.create({
      clientUserId: new Types.ObjectId(clientUserId),
      riderId: shipment.riderID,
      shipmentId: shipment._id,
      rating,
      comment,
    });

    const rider = await Rider.findById(shipment.riderID).select("userId").lean().exec();
    const riderUser = rider?.userId ? await User.findById(rider.userId).select("firstName lastName").lean().exec() : null;
    const riderName = riderUser
      ? `${riderUser.firstName ?? ""} ${riderUser.lastName ?? ""}`.trim() || "Rider"
      : "Rider";

    return toDto(created, riderName);
  }

  async listForClient(clientUserId: string): Promise<FeedbackDto[]> {
    const list = await Feedback.find({ clientUserId: new Types.ObjectId(clientUserId) })
      .sort({ createdAt: -1 })
      .lean()
      .exec();

    const riderIds = Array.from(new Set(list.map((f) => f.riderId?.toString()).filter(Boolean)));
    const riders = await Rider.find({ _id: { $in: riderIds } }).select("userId").lean().exec();
    const riderToUserId = new Map<string, string>();
    for (const rider of riders) {
      if (rider._id && rider.userId) {
        riderToUserId.set(String(rider._id), String(rider.userId));
      }
    }

    const userIds = Array.from(new Set(Array.from(riderToUserId.values())));
    const users = await User.find({ _id: { $in: userIds } }).select("firstName lastName").lean().exec();
    const userNameById = new Map<string, string>();
    for (const user of users) {
      const name = `${user.firstName ?? ""} ${user.lastName ?? ""}`.trim() || "Rider";
      userNameById.set(String(user._id), name);
    }

    return list.map((f) => {
      const riderId = String(f.riderId);
      const userId = riderToUserId.get(riderId);
      const riderName = userId ? userNameById.get(userId) ?? "Rider" : "Rider";
      return {
        _id: String(f._id),
        clientUserId: String(f.clientUserId),
        riderId,
        shipmentId: String(f.shipmentId),
        rating: f.rating,
        comment: f.comment ?? "",
        riderName,
        createdAt: new Date(f.createdAt).toISOString(),
        updatedAt: new Date(f.updatedAt).toISOString(),
      };
    });
  }
}
