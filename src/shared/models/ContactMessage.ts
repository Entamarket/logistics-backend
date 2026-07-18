import mongoose, { Document, Schema } from "mongoose";
import { ContactMessageEmailDeliveryStatus } from "../lib/enums";

export interface IContactMessage extends Document {
  name: string;
  email: string;
  phone: string;
  subject: string;
  message: string;
  readAt?: Date | null;
  emailDeliveryStatus: string;
  createdAt: Date;
  updatedAt: Date;
}

const contactMessageSchema = new Schema<IContactMessage>(
  {
    name: {
      type: String,
      required: [true, "Name is required"],
      trim: true,
      maxlength: 120,
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      trim: true,
      lowercase: true,
      maxlength: 254,
    },
    phone: {
      type: String,
      required: [true, "Phone number is required"],
      trim: true,
      maxlength: 30,
    },
    subject: {
      type: String,
      trim: true,
      maxlength: 200,
      default: "",
    },
    message: {
      type: String,
      required: [true, "Message is required"],
      trim: true,
      maxlength: 5000,
    },
    readAt: {
      type: Date,
      default: null,
    },
    emailDeliveryStatus: {
      type: String,
      enum: Object.values(ContactMessageEmailDeliveryStatus),
      default: ContactMessageEmailDeliveryStatus.PENDING,
      index: true,
    },
  },
  { timestamps: true }
);

contactMessageSchema.index({ createdAt: -1 });

export const ContactMessage = mongoose.model<IContactMessage>("ContactMessage", contactMessageSchema);
