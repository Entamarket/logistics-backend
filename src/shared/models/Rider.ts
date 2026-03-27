import mongoose, { Schema, Document, Types } from "mongoose";
import { RiderStatus } from "../lib/enums";

export interface IRiderLocation {
  type: "Point";
  coordinates: [number, number];
}

export interface IRider extends Document {
  userId: Types.ObjectId;
  status: string;
  isAvailable: boolean;
  isVerified: boolean;
  location?: IRiderLocation;
  createdAt: Date;
  updatedAt: Date;
}

const riderLocationSchema = new Schema<IRiderLocation>(
  {
    type: {
      type: String,
      enum: ["Point"],
      required: true,
    },
    coordinates: {
      type: [Number],
      required: true,
      validate: {
        validator(v: unknown) {
          return (
            Array.isArray(v) &&
            v.length === 2 &&
            typeof v[0] === "number" &&
            typeof v[1] === "number" &&
            v[0] >= -180 &&
            v[0] <= 180 &&
            v[1] >= -90 &&
            v[1] <= 90
          );
        },
        message: "coordinates must be [longitude, latitude] in valid ranges",
      },
    },
  },
  { _id: false }
);

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
    location: {
      type: riderLocationSchema,
      required: false,
    },
  },
  { timestamps: true }
);

riderSchema.index({ location: "2dsphere" }, { sparse: true });

export const Rider = mongoose.model<IRider>("Rider", riderSchema);
