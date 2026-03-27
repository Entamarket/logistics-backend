import { Types } from "mongoose";
import { Notification, INotification } from "../../shared/models/Notification";
import { NotificationType } from "../../shared/lib/enums";
import { broadcastToUser } from "../../realtime/wsHub";

export interface NotificationDto {
  _id: string;
  userId: string;
  type: string;
  title: string;
  message: string;
  read: boolean;
  relatedShipmentId: string | null;
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
    });
    const dto = toDto(doc);
    broadcastToUser(userId, { event: "notification", notification: dto });
    const count = await this.countUnread(userId);
    broadcastToUser(userId, { event: "unread_count", count });
    return dto;
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
