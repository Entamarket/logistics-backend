import mongoose, { Schema, Document, Types } from "mongoose";
import { RiderStatus } from "../lib/enums";

export interface IRider extends Document {
  userId: Types.ObjectId;
  status: string;
  isAvailable: boolean;
  isVerified: boolean;
  createdAt: Date;
  updatedAt: Date;
}

const riderSchema = new Schema<IRider>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: true,
      unique: true,
    },
    status: {
      type: String,
      enum: Object.values(RiderStatus),
      default: RiderStatus.PENDING,
    },
    isAvailable: {
      type: Boolean,
      default: false,
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true }
);

export const Rider = mongoose.model<IRider>("Rider", riderSchema);
