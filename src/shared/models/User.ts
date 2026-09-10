import mongoose, { Schema, Document } from "mongoose";
import { UserAccountStatus } from "../lib/enums";

export interface IUser extends Document {
  firstName: string;
  lastName: string;
  email: string;
  phone?: string;
  password: string;
  role: string;
  status: string;
  isEmailVerified: boolean;
  createdAt: Date;
  updatedAt: Date;
}

const userSchema = new Schema<IUser>(
  {
    firstName: {
      type: String,
      required: [true, "First name is required"],
      trim: true,
    },
    lastName: {
      type: String,
      required: [true, "Last name is required"],
      trim: true,
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, "Please provide a valid email"],
    },
    phone: {
      type: String,
      required: false,
      trim: true,
      default: undefined,
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: [8, "Password must be at least 8 characters"],
    },
    role: {
      type: String,
      enum: ["client", "admin", "rider"],
      default: "client",
    },
    status: {
      type: String,
      enum: Object.values(UserAccountStatus),
      default: UserAccountStatus.ACTIVE,
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  }
);

/** Unique when set; multiple users may omit phone (field absent). */
userSchema.index({ phone: 1 }, { unique: true, sparse: true });

export const User = mongoose.model<IUser>("User", userSchema);

