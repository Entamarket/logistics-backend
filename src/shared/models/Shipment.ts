import mongoose, { Schema, Document, Types } from "mongoose";
import { ShipmentStatus, DeliveryType, PaymentStatus } from "../lib/enums";

export interface ISenderDetails {
  fullName: string;
  address: string;
  phone: string;
}

export interface IRecipientDetails {
  fullName: string;
  address: string;
  phone: string;
}

export interface IPackageDetails {
  type: string;
  weight: number;
  dimensions: number;
  quantity: number;
  note?: string;
}

export interface ITimelineEntry {
  status: string;
  timestamp: Date;
}

export interface IShipment extends Document {
  userId: Types.ObjectId;
  status: string;
  deliveryType: string;
  pickupWindowStart?: Date;
  pickupWindowEnd?: Date;
  riderID: Types.ObjectId | null;
  price: number;
  paymentStatus: string;
  timeline: ITimelineEntry[];
  senderDetails: ISenderDetails;
  recipientDetails: IRecipientDetails;
  packageDetails: IPackageDetails;
  createdAt: Date;
  updatedAt: Date;
}

const senderDetailsSchema = new Schema<ISenderDetails>(
  {
    fullName: { type: String, required: [true, "Sender full name is required"], trim: true },
    address: { type: String, required: [true, "Sender address is required"], trim: true },
    phone: { type: String, required: [true, "Sender phone is required"], trim: true },
  },
  { _id: false }
);

const recipientDetailsSchema = new Schema<IRecipientDetails>(
  {
    fullName: { type: String, required: [true, "Recipient full name is required"], trim: true },
    address: { type: String, required: [true, "Recipient address is required"], trim: true },
    phone: { type: String, required: [true, "Recipient phone is required"], trim: true },
  },
  { _id: false }
);

const packageDetailsSchema = new Schema<IPackageDetails>(
  {
    type: { type: String, required: [true, "Package type is required"], trim: true },
    weight: { type: Number, required: [true, "Weight is required"], min: 0 },
    dimensions: { type: Number, required: [true, "Dimensions are required"], min: 0 },
    quantity: { type: Number, required: [true, "Quantity is required"], min: 1 },
    note: { type: String, trim: true, default: "" },
  },
  { _id: false }
);

const timelineEntrySchema = new Schema<ITimelineEntry>(
  {
    status: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
  },
  { _id: false }
);

const shipmentSchema = new Schema<IShipment>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      required: [true, "User ID is required"],
      ref: "User",
    },
    status: {
      type: String,
      enum: Object.values(ShipmentStatus),
      default: ShipmentStatus.PENDING,
    },
    deliveryType: {
      type: String,
      enum: Object.values(DeliveryType),
      required: [true, "Delivery type is required"],
    },
    pickupWindowStart: { type: Date },
    pickupWindowEnd: { type: Date },
    riderID: {
      type: Schema.Types.ObjectId,
      ref: "Rider",
      default: null,
    },
    price: {
      type: Number,
      required: [true, "Price is required"],
    },
    paymentStatus: {
      type: String,
      enum: Object.values(PaymentStatus),
      default: PaymentStatus.PENDING,
    },
    timeline: {
      type: [timelineEntrySchema],
      default: [],
    },
    senderDetails: { type: senderDetailsSchema, required: true },
    recipientDetails: { type: recipientDetailsSchema, required: true },
    packageDetails: { type: packageDetailsSchema, required: true },
  },
  { timestamps: true }
);

export const Shipment = mongoose.model<IShipment>("Shipment", shipmentSchema);
