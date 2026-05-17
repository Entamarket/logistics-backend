import mongoose, { Document, Schema, Types } from "mongoose";
import { ComplaintReporterType, ComplaintStatus } from "../lib/enums";

export interface IComplaint extends Document {
  userId: Types.ObjectId;
  reporterType: string;
  subject: string;
  message: string;
  phone: string;
  relatedShipmentId?: Types.ObjectId | null;
  status: string;
  createdAt: Date;
  updatedAt: Date;
}

const complaintSchema = new Schema<IComplaint>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    reporterType: {
      type: String,
      enum: Object.values(ComplaintReporterType),
      required: true,
      index: true,
    },
    subject: {
      type: String,
      required: [true, "Subject is required"],
      trim: true,
      maxlength: 200,
    },
    message: {
      type: String,
      required: [true, "Message is required"],
      trim: true,
      maxlength: 5000,
    },
    phone: {
      type: String,
      required: [true, "Phone number is required"],
      trim: true,
      maxlength: 30,
    },
    relatedShipmentId: {
      type: Schema.Types.ObjectId,
      ref: "Shipment",
      default: null,
    },
    status: {
      type: String,
      enum: Object.values(ComplaintStatus),
      default: ComplaintStatus.OPEN,
      index: true,
    },
  },
  { timestamps: true }
);

export const Complaint = mongoose.model<IComplaint>("Complaint", complaintSchema);
