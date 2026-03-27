import bcrypt from "bcrypt";
import { Types } from "mongoose";
import { Rider, IRider, IRiderLocation } from "../../shared/models/Rider";
import { User } from "../../shared/models/User";
import { RiderStatus } from "../../shared/lib/enums";
import { sendRiderCredentialsEmail } from "../../config/email";
import { logger } from "../../shared/lib/logger";

const NEAR_METERS_PRIMARY = 5000;
const NEAR_METERS_FALLBACK = 10000;

export interface CreateRiderBody {
  firstName: string;
  lastName: string;
  email: string;
  phone: string;
  password: string;
}

export interface UpdateRiderBody {
  status?: string;
  isAvailable?: boolean;
  isVerified?: boolean;
  firstName?: string;
  lastName?: string;
  phone?: string;
  email?: string;
}

export class RiderService {
  async create(data: CreateRiderBody): Promise<IRider> {
    const existingUser = await User.findOne({ email: data.email.toLowerCase() });
    if (existingUser) {
      throw new Error("User with this email already exists");
    }
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(data.password, saltRounds);
    const user = await User.create({
      firstName: data.firstName,
      lastName: data.lastName,
      email: data.email.toLowerCase().trim(),
      phone: data.phone,
      password: hashedPassword,
      role: "rider",
      isEmailVerified: false,
    });
    const rider = await Rider.create({
      userId: user._id,
      status: RiderStatus.ACTIVE,
      isAvailable: true,
      isVerified: true,
    });
    sendRiderCredentialsEmail(user.email, user.firstName, data.password).catch((error) => {
      logger.error("Failed to send rider credentials email", {
        message: error instanceof Error ? error.message : String(error),
        email: user.email,
      });
    });
    return rider;
  }

  async findAll(): Promise<IRider[]> {
    const riders = await Rider.find()
      .sort({ createdAt: -1 })
      .populate("userId", "firstName lastName email phone")
      .lean()
      .exec();
    return riders as unknown as IRider[];
  }

  async findById(id: string): Promise<IRider | null> {
    return Rider.findById(id).populate("userId", "firstName lastName email phone").exec();
  }

  async update(id: string, data: UpdateRiderBody): Promise<IRider | null> {
    const rider = await Rider.findById(id).exec();
    if (!rider) return null;
    const riderUpdates: Record<string, unknown> = {};
    if (data.status !== undefined) riderUpdates.status = data.status;
    if (data.isAvailable !== undefined) riderUpdates.isAvailable = data.isAvailable;
    if (data.isVerified !== undefined) riderUpdates.isVerified = data.isVerified;
    if (Object.keys(riderUpdates).length > 0) {
      await Rider.findByIdAndUpdate(id, { $set: riderUpdates }, { runValidators: true }).exec();
    }
    const userUpdates: Record<string, unknown> = {};
    if (data.firstName !== undefined) userUpdates.firstName = data.firstName;
    if (data.lastName !== undefined) userUpdates.lastName = data.lastName;
    if (data.phone !== undefined) userUpdates.phone = data.phone;
    if (data.email !== undefined) userUpdates.email = data.email.toLowerCase().trim();
    if (Object.keys(userUpdates).length > 0) {
      await User.findByIdAndUpdate(rider.userId, { $set: userUpdates }, { runValidators: true }).exec();
    }
    return Rider.findById(id).populate("userId", "firstName lastName email phone").exec();
  }

  async updateStatus(id: string, status: "active" | "suspended" | "blocked"): Promise<IRider | null> {
    return Rider.findByIdAndUpdate(
      id,
      { $set: { status } },
      { new: true, runValidators: true }
    )
      .populate("userId", "firstName lastName email phone")
      .exec();
  }

  /**
   * Atomically claims the nearest available rider within maxDistanceMeters (MongoDB returns candidates sorted by distance).
   */
  private async tryClaimNearestInRadius(
    longitude: number,
    latitude: number,
    maxDistanceMeters: number,
    excludeRiderIds: Types.ObjectId[]
  ): Promise<IRider | null> {
    const geoFilter: Record<string, unknown> = {
      status: RiderStatus.ACTIVE,
      isVerified: true,
      isAvailable: true,
      location: {
        $nearSphere: {
          $geometry: {
            type: "Point",
            coordinates: [longitude, latitude],
          },
          $maxDistance: maxDistanceMeters,
        },
      },
    };
    if (excludeRiderIds.length > 0) {
      geoFilter._id = { $nin: excludeRiderIds };
    }
    const candidates = await Rider.find(geoFilter).limit(10).exec();

    for (const candidate of candidates) {
      const claimed = await Rider.findOneAndUpdate(
        { _id: candidate._id, isAvailable: true },
        { $set: { isAvailable: false } },
        { new: true }
      ).exec();
      if (claimed) return claimed;
    }
    return null;
  }

  /**
   * Finds nearest active/verified/available rider with a GeoJSON location; tries 5 km then 10 km.
   * Sets isAvailable to false on the claimed rider.
   * @param excludeRiderIds riders to skip (e.g. already declined this shipment)
   */
  async claimNearestAvailableRider(
    longitude: number,
    latitude: number,
    excludeRiderIds: Types.ObjectId[] = []
  ): Promise<IRider | null> {
    let rider = await this.tryClaimNearestInRadius(longitude, latitude, NEAR_METERS_PRIMARY, excludeRiderIds);
    if (!rider) {
      rider = await this.tryClaimNearestInRadius(longitude, latitude, NEAR_METERS_FALLBACK, excludeRiderIds);
    }
    return rider;
  }

  async updateLocationByUserId(userId: string, longitude: number, latitude: number): Promise<IRider | null> {
    const location: IRiderLocation = {
      type: "Point",
      coordinates: [longitude, latitude],
    };
    return Rider.findOneAndUpdate(
      { userId },
      { $set: { location } },
      { new: true, runValidators: true }
    )
      .populate("userId", "firstName lastName email phone")
      .exec();
  }

  async findByUserId(userId: string): Promise<IRider | null> {
    return Rider.findOne({ userId }).populate("userId", "firstName lastName email phone").exec();
  }

  async setRiderAvailable(riderId: string, available: boolean): Promise<void> {
    await Rider.findByIdAndUpdate(riderId, { $set: { isAvailable: available } }, { runValidators: true }).exec();
  }
}
