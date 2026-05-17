import { Types } from "mongoose";
import { Complaint, IComplaint } from "../../shared/models/Complaint";
import { ComplaintReporterType, ComplaintStatus } from "../../shared/lib/enums";
import { NotificationService } from "../notification/notification.service";

export interface ComplaintDto {
  id: string;
  userId: string;
  reporterType: string;
  subject: string;
  message: string;
  phone: string;
  relatedShipmentId: string | null;
  status: string;
  createdAt: string;
  updatedAt: string;
}

export interface ComplaintReporterDto {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  phone: string;
}

export interface AdminComplaintDto extends ComplaintDto {
  reporter: ComplaintReporterDto;
}

type PopulatedUser = {
  _id: Types.ObjectId;
  firstName: string;
  lastName: string;
  email: string;
  phone: string;
};

function isPopulatedUser(v: unknown): v is PopulatedUser {
  return v != null && typeof v === "object" && "firstName" in v && "email" in v;
}

function toDto(doc: IComplaint): ComplaintDto {
  return {
    id: doc._id.toString(),
    userId: doc.userId.toString(),
    reporterType: doc.reporterType,
    subject: doc.subject,
    message: doc.message,
    phone: doc.phone ?? "",
    relatedShipmentId: doc.relatedShipmentId ? doc.relatedShipmentId.toString() : null,
    status: doc.status,
    createdAt: doc.createdAt.toISOString(),
    updatedAt: doc.updatedAt.toISOString(),
  };
}

function mapReporter(user: unknown): ComplaintReporterDto {
  if (!isPopulatedUser(user)) {
    return { id: "", firstName: "", lastName: "", email: "", phone: "" };
  }
  return {
    id: user._id.toString(),
    firstName: user.firstName,
    lastName: user.lastName,
    email: user.email,
    phone: user.phone,
  };
}

function toAdminDto(doc: IComplaint & { userId: PopulatedUser | Types.ObjectId }): AdminComplaintDto {
  return {
    ...toDto(doc),
    reporter: mapReporter(doc.userId),
  };
}

export class ComplaintService {
  private notificationService = new NotificationService();

  async create(params: {
    userId: string;
    role: string;
    subject: string;
    message: string;
    phone: string;
    relatedShipmentId?: string;
  }): Promise<ComplaintDto> {
    const { userId, role, subject, message, phone } = params;
    if (role !== ComplaintReporterType.CLIENT && role !== ComplaintReporterType.RIDER) {
      throw new Error("Only clients and riders can submit complaints");
    }
    const trimmedSubject = subject.trim();
    const trimmedMessage = message.trim();
    const trimmedPhone = phone.trim();
    if (!trimmedSubject) throw new Error("Subject is required");
    if (!trimmedMessage) throw new Error("Message is required");
    if (!trimmedPhone) throw new Error("Phone number is required");
    if (trimmedPhone.length < 6) {
      throw new Error("Please enter a valid phone number");
    }
    if (trimmedMessage.length < 10) {
      throw new Error("Please provide at least 10 characters in your complaint message");
    }

    let relatedShipmentId: Types.ObjectId | null = null;
    if (params.relatedShipmentId?.trim()) {
      if (!Types.ObjectId.isValid(params.relatedShipmentId)) {
        throw new Error("Invalid shipment id");
      }
      relatedShipmentId = new Types.ObjectId(params.relatedShipmentId.trim());
    }

    const doc = await Complaint.create({
      userId: new Types.ObjectId(userId),
      reporterType: role,
      subject: trimmedSubject,
      message: trimmedMessage,
      phone: trimmedPhone,
      relatedShipmentId,
      status: ComplaintStatus.OPEN,
    });
    const dto = toDto(doc);
    void this.notificationService.notifyAdminsNewComplaint({
      complaintId: dto.id,
      reporterType: role,
      subject: trimmedSubject,
    });
    return dto;
  }

  async listForUser(userId: string): Promise<ComplaintDto[]> {
    const rows = await Complaint.find({ userId: new Types.ObjectId(userId) })
      .sort({ createdAt: -1 })
      .limit(50)
      .exec();
    return rows.map(toDto);
  }

  async listForAdmin(query: { reporterType?: string; status?: string; limit?: number }): Promise<AdminComplaintDto[]> {
    const limit = Math.min(Math.max(query.limit ?? 100, 1), 200);
    const filter: Record<string, unknown> = {};
    if (query.reporterType === ComplaintReporterType.CLIENT || query.reporterType === ComplaintReporterType.RIDER) {
      filter.reporterType = query.reporterType;
    }
    if (
      query.status === ComplaintStatus.OPEN ||
      query.status === ComplaintStatus.IN_REVIEW ||
      query.status === ComplaintStatus.RESOLVED
    ) {
      filter.status = query.status;
    }

    const rows = await Complaint.find(filter)
      .populate("userId", "firstName lastName email phone")
      .sort({ createdAt: -1 })
      .limit(limit)
      .exec();

    return rows.map((row) => toAdminDto(row as IComplaint & { userId: PopulatedUser | Types.ObjectId }));
  }

  async getByIdForAdmin(id: string): Promise<AdminComplaintDto | null> {
    if (!Types.ObjectId.isValid(id)) return null;
    const doc = await Complaint.findById(id)
      .populate("userId", "firstName lastName email phone")
      .exec();
    if (!doc) return null;
    return toAdminDto(doc as IComplaint & { userId: PopulatedUser | Types.ObjectId });
  }

  async updateStatus(id: string, status: string): Promise<AdminComplaintDto | null> {
    if (
      status !== ComplaintStatus.OPEN &&
      status !== ComplaintStatus.IN_REVIEW &&
      status !== ComplaintStatus.RESOLVED
    ) {
      throw new Error("status must be 'open', 'in_review', or 'resolved'");
    }
    const doc = await Complaint.findByIdAndUpdate(id, { $set: { status } }, { new: true, runValidators: true })
      .populate("userId", "firstName lastName email phone")
      .exec();
    if (!doc) return null;
    return toAdminDto(doc as IComplaint & { userId: PopulatedUser | Types.ObjectId });
  }
}
