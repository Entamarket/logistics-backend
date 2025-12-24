import mongoose, { Schema, Document, Types } from "mongoose";
import { EmailVerificationPurpose } from "../lib/enums";

export interface IEmailVerification extends Document {
  userId: Types.ObjectId;
  otpHash: string;
  purpose: string;
  expiresAt: Date;
  attempts: number;
  createdAt: Date;
}

const emailVerificationSchema = new Schema<IEmailVerification>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      required: [true, "User ID is required"],
      ref: "User",
    },
    otpHash: {
      type: String,
      required: [true, "OTP hash is required"],
    },
    purpose: {
      type: String,
      required: [true, "Purpose is required"],
      enum: Object.values(EmailVerificationPurpose),
      default: EmailVerificationPurpose.EMAIL_VERIFICATION,
    },
    expiresAt: {
      type: Date,
      required: [true, "Expiration date is required"],
    },
    attempts: {
      type: Number,
      default: 0,
    },
  },
  {
    timestamps: true,
  }
);

// Create TTL index on expiresAt field
// expireAfterSeconds: 0 means documents expire when expiresAt date is reached
emailVerificationSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export const EmailVerification = mongoose.model<IEmailVerification>(
  "EmailVerification",
  emailVerificationSchema
);

