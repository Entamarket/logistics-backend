import { Types } from "mongoose";
import { Notification, INotification } from "../../shared/models/Notification";
import { User } from "../../shared/models/User";
import { NotificationType } from "../../shared/lib/enums";
import { broadcastToUser } from "../../realtime/wsHub";
import { logger } from "../../shared/lib/logger";

export interface NotificationDto {
  _id: string;
  userId: string;
  type: string;
  title: string;
  message: string;
  read: boolean;
  relatedShipmentId: string | null;
  relatedComplaintId: string | null;
  createdAt: string;
  updatedAt: string;
}

function toDto(doc: INotification): NotificationDto {
  return {
    _id: doc._id.toString(),
    userId: doc.userId.toString(),
    type: doc.type,
    title: doc.title,
    message: doc.message,
    read: doc.read,
    relatedShipmentId: doc.relatedShipmentId ? doc.relatedShipmentId.toString() : null,
    relatedComplaintId: doc.relatedComplaintId ? doc.relatedComplaintId.toString() : null,
    createdAt: doc.createdAt.toISOString(),
    updatedAt: doc.updatedAt.toISOString(),
  };
}

export class NotificationService {
  async createForUser(
    userId: string,
    params: {
      type: NotificationType;
      title: string;
      message: string;
      relatedShipmentId?: string | null;
      relatedComplaintId?: string | null;
    }
  ): Promise<NotificationDto> {
    const doc = await Notification.create({
      userId: new Types.ObjectId(userId),
      type: params.type,
      title: params.title,
      message: params.message,
      read: false,
      relatedShipmentId: params.relatedShipmentId
        ? new Types.ObjectId(params.relatedShipmentId)
        : null,
      relatedComplaintId: params.relatedComplaintId
        ? new Types.ObjectId(params.relatedComplaintId)
        : null,
    });
    const dto = toDto(doc);
    broadcastToUser(userId, { event: "notification", notification: dto });
    const count = await this.countUnread(userId);
    broadcastToUser(userId, { event: "unread_count", count });
    return dto;
  }

  async notifyAdminsShipmentOffered(params: {
    shipmentId: string;
    riderName?: string;
  }): Promise<void> {
    try {
      const admins = await User.find({ role: "admin" }).select("_id").lean().exec();
      if (admins.length === 0) return;

      const title = "Shipment offered to rider";
      const message =
        params.riderName?.trim()
          ? `Offer sent to ${params.riderName.trim()}. Open the shipment to reassign if needed.`
          : "A shipment offer was sent to a rider. Open the shipment to reassign if needed.";

      await Promise.all(
        admins.map((admin) =>
          this.createForUser(String(admin._id), {
            type: NotificationType.SHIPMENT_OFFERED,
            title,
            message,
            relatedShipmentId: params.shipmentId,
          })
        )
      );
    } catch (e) {
      logger.error("Failed to notify admins of shipment offer", {
        message: e instanceof Error ? e.message : String(e),
        shipmentId: params.shipmentId,
        riderName: params.riderName,
      });
    }
  }

  async notifyAdminsNewComplaint(params: {
    complaintId: string;
    reporterType: string;
    subject: string;
  }): Promise<void> {
    try {
      const admins = await User.find({ role: "admin" }).select("_id").lean().exec();
      if (admins.length === 0) return;

      const reporterLabel = params.reporterType === "rider" ? "Rider" : "Client";
      const title = `New ${reporterLabel.toLowerCase()} complaint`;
      const message = `${reporterLabel} complaint: "${params.subject}". Open Complaints to review.`;

      await Promise.all(
        admins.map((admin) =>
          this.createForUser(String(admin._id), {
            type: NotificationType.COMPLAINT_SUBMITTED,
            title,
            message,
            relatedComplaintId: params.complaintId,
          })
        )
      );
    } catch (e) {
      logger.error("Failed to notify admins of new complaint", {
        message: e instanceof Error ? e.message : String(e),
      });
    }
  }

  async listForUser(userId: string, limit = 50): Promise<NotificationDto[]> {
    const list = await Notification.find({ userId: new Types.ObjectId(userId) })
      .sort({ createdAt: -1 })
      .limit(limit)
      .exec();
    return list.map((d) => toDto(d));
  }

  async countUnread(userId: string): Promise<number> {
    return Notification.countDocuments({
      userId: new Types.ObjectId(userId),
      read: false,
    }).exec();
  }

  async markRead(notificationId: string, userId: string): Promise<NotificationDto | null> {
    const doc = await Notification.findOneAndUpdate(
      { _id: notificationId, userId: new Types.ObjectId(userId) },
      { $set: { read: true } },
      { new: true }
    ).exec();
    if (!doc) return null;
    const dto = toDto(doc);
    const count = await this.countUnread(userId);
    broadcastToUser(userId, { event: "unread_count", count });
    return dto;
  }

  async markAllRead(userId: string): Promise<number> {
    const res = await Notification.updateMany(
      { userId: new Types.ObjectId(userId), read: false },
      { $set: { read: true } }
    ).exec();
    broadcastToUser(userId, { event: "unread_count", count: 0 });
    return res.modifiedCount;
  }
}
