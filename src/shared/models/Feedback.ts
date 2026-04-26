import mongoose, { Document, Schema, Types } from "mongoose";

export interface IFeedback extends Document {
  clientUserId: Types.ObjectId;
  riderId: Types.ObjectId;
  shipmentId: Types.ObjectId;
  rating: number;
  comment?: string;
  createdAt: Date;
  updatedAt: Date;
}

const feedbackSchema = new Schema<IFeedback>(
  {
    clientUserId: {
      type: Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    riderId: {
      type: Schema.Types.ObjectId,
      ref: "Rider",
      required: true,
      index: true,
    },
    shipmentId: {
      type: Schema.Types.ObjectId,
      ref: "Shipment",
      required: true,
      index: true,
    },
    rating: {
      type: Number,
      required: true,
      min: 1,
      max: 5,
    },
    comment: {
      type: String,
      trim: true,
      default: "",
      maxlength: 1000,
    },
  },
  { timestamps: true }
);

feedbackSchema.index({ shipmentId: 1, clientUserId: 1 }, { unique: true });

export const Feedback = mongoose.model<IFeedback>("Feedback", feedbackSchema);
