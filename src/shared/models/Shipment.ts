import mongoose, { Schema, Document, Types } from "mongoose";
import { ShipmentStatus, DeliveryType, PaymentStatus } from "../lib/enums";

export interface ISenderDetails {
  fullName: string;
  address: string;
  phone: string;
  /** ISO 3166-1 alpha-2 country code (e.g. NG). */
  country?: string;
  state?: string;
}

export interface IRecipientDetails {
  fullName: string;
  address: string;
  phone: string;
  country?: string;
  state?: string;
}

export interface IPackageDetails {
  type: string;
  weight: number;
  lengthCm: number;
  widthCm: number;
  heightCm: number;
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
  /** Pickup point (WGS84) for rider matching / reassignment. */
  pickupLongitude?: number;
  pickupLatitude?: number;
  /** Drop-off point (WGS84); optional, for maps / directions. */
  recipientLongitude?: number;
  recipientLatitude?: number;
  /** When the current rider must accept; after this, offer moves to another rider. */
  riderResponseDeadline?: Date;
  /** Riders who already declined or timed out on this shipment (exclude from next match). */
  declinedRiderIds?: Types.ObjectId[];
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
    country: { type: String, trim: true, uppercase: true, default: "NG" },
    state: { type: String, trim: true, default: "" },
  },
  { _id: false }
);

const recipientDetailsSchema = new Schema<IRecipientDetails>(
  {
    fullName: { type: String, required: [true, "Recipient full name is required"], trim: true },
    address: { type: String, required: [true, "Recipient address is required"], trim: true },
    phone: { type: String, required: [true, "Recipient phone is required"], trim: true },
    country: { type: String, trim: true, uppercase: true, default: "NG" },
    state: { type: String, trim: true, default: "" },
  },
  { _id: false }
);

const packageDetailsSchema = new Schema<IPackageDetails>(
  {
    type: { type: String, required: [true, "Package type is required"], trim: true },
    weight: { type: Number, required: [true, "Weight is required"], min: 0 },
    lengthCm: { type: Number, required: [true, "Length is required"], min: 0 },
    widthCm: { type: Number, required: [true, "Width is required"], min: 0 },
    heightCm: { type: Number, required: [true, "Height is required"], min: 0 },
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
    pickupLongitude: { type: Number },
    pickupLatitude: { type: Number },
    recipientLongitude: { type: Number },
    recipientLatitude: { type: Number },
    riderResponseDeadline: { type: Date },
    declinedRiderIds: {
      type: [{ type: Schema.Types.ObjectId, ref: "Rider" }],
      default: [],
    },
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
