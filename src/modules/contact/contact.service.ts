import { Types } from "mongoose";
import { ContactMessage, IContactMessage } from "../../shared/models/ContactMessage";
import { ContactMessageEmailDeliveryStatus } from "../../shared/lib/enums";
import { sendContactMessageNotificationEmail } from "../../config/email";
import { logger } from "../../shared/lib/logger";

export interface ContactMessageDto {
  id: string;
  name: string;
  email: string;
  phone: string;
  subject: string;
  message: string;
  readAt: string | null;
  emailDeliveryStatus: string;
  createdAt: string;
  updatedAt: string;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function toDto(doc: IContactMessage): ContactMessageDto {
  return {
    id: doc._id.toString(),
    name: doc.name,
    email: doc.email,
    phone: doc.phone,
    subject: doc.subject || "",
    message: doc.message,
    readAt: doc.readAt ? new Date(doc.readAt).toISOString() : null,
    emailDeliveryStatus: doc.emailDeliveryStatus,
    createdAt: doc.createdAt.toISOString(),
    updatedAt: doc.updatedAt.toISOString(),
  };
}

export class ContactService {
  async create(params: {
    name: string;
    email: string;
    phone: string;
    subject?: string;
    message: string;
  }): Promise<ContactMessageDto> {
    const name = params.name?.trim() ?? "";
    const email = params.email?.trim().toLowerCase() ?? "";
    const phone = params.phone?.trim() ?? "";
    const subject = params.subject?.trim() ?? "";
    const message = params.message?.trim() ?? "";

    if (!name) throw new Error("Name is required");
    if (name.length > 120) throw new Error("Name must be at most 120 characters");
    if (!email) throw new Error("Email is required");
    if (!EMAIL_RE.test(email)) throw new Error("Please enter a valid email address");
    if (email.length > 254) throw new Error("Email must be at most 254 characters");
    if (!phone) throw new Error("Phone number is required");
    if (phone.length < 6 || phone.length > 30) {
      throw new Error("Please enter a valid phone number");
    }
    if (subject.length > 200) throw new Error("Subject must be at most 200 characters");
    if (!message) throw new Error("Message is required");
    if (message.length < 10) throw new Error("Please provide at least 10 characters in your message");
    if (message.length > 5000) throw new Error("Message must be at most 5000 characters");

    const doc = await ContactMessage.create({
      name,
      email,
      phone,
      subject,
      message,
      emailDeliveryStatus: ContactMessageEmailDeliveryStatus.PENDING,
    });

    try {
      const delivery = await sendContactMessageNotificationEmail({
        name,
        email,
        phone,
        subject: subject || "Entamarket Logistics inquiry",
        message,
      });
      doc.emailDeliveryStatus =
        delivery === "sent"
          ? ContactMessageEmailDeliveryStatus.SENT
          : delivery === "skipped"
            ? ContactMessageEmailDeliveryStatus.SKIPPED
            : ContactMessageEmailDeliveryStatus.FAILED;
      await doc.save();
    } catch (e) {
      logger.error("Unexpected error sending contact message email", {
        messageId: doc._id.toString(),
        message: e instanceof Error ? e.message : String(e),
      });
      doc.emailDeliveryStatus = ContactMessageEmailDeliveryStatus.FAILED;
      await doc.save();
    }

    return toDto(doc);
  }

  async listForAdmin(params?: { limit?: number; unreadOnly?: boolean }): Promise<ContactMessageDto[]> {
    const limit = Math.min(Math.max(params?.limit ?? 100, 1), 200);
    const filter: Record<string, unknown> = {};
    if (params?.unreadOnly) {
      filter.readAt = null;
    }
    const rows = await ContactMessage.find(filter).sort({ createdAt: -1 }).limit(limit).exec();
    return rows.map(toDto);
  }

  async getByIdForAdmin(id: string): Promise<ContactMessageDto | null> {
    if (!Types.ObjectId.isValid(id)) {
      throw new Error("Invalid message id");
    }
    const doc = await ContactMessage.findById(id).exec();
    if (!doc) return null;
    if (!doc.readAt) {
      doc.readAt = new Date();
      await doc.save();
    }
    return toDto(doc);
  }
}
