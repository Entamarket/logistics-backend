import bcrypt from "bcrypt";
import { Types } from "mongoose";
import { Rider, IRider, IRiderLocation } from "../../shared/models/Rider";
import { User } from "../../shared/models/User";
import { Shipment } from "../../shared/models/Shipment";
import { RiderStatus, ShipmentStatus } from "../../shared/lib/enums";
import { sendRiderCredentialsEmail } from "../../config/email";
import { logger } from "../../shared/lib/logger";
import { broadcastToUser } from "../../realtime/wsHub";

const NEAR_METERS_PRIMARY = 5000;
const NEAR_METERS_FALLBACK = 10000;
/** Fixed rider pay per completed delivery (NGN). */
export const RIDER_EARNINGS_PER_DELIVERY_NGN = 500;
const EARNINGS_TIMEZONE = "Africa/Lagos";

export interface RiderDailyEarningsBucket {
  date: string;
  label: string;
  deliveredCount: number;
  earningsNgn: number;
}

export interface RiderEarningsSummary {
  ratePerDelivery: number;
  days: number;
  timezone: string;
  daily: RiderDailyEarningsBucket[];
  periodDeliveredCount: number;
  periodEarningsNgn: number;
  allTimeDeliveredCount: number;
  allTimeEarningsNgn: number;
}

type LeanDeliveredShipment = {
  timeline?: { status: string; timestamp?: Date }[];
  updatedAt?: Date;
};

function isValidDate(d: Date): boolean {
  return d instanceof Date && !Number.isNaN(d.getTime());
}

function toValidDate(value: unknown): Date | null {
  if (value == null) return null;
  const d = value instanceof Date ? value : new Date(value as string | number);
  return isValidDate(d) ? d : null;
}

function deliveredAtFromDoc(row: LeanDeliveredShipment): Date | null {
  const tl = row.timeline;
  if (tl?.length) {
    const deliveredEntries = tl.filter((e) => e.status === ShipmentStatus.DELIVERED);
    if (deliveredEntries.length) {
      const last = deliveredEntries[deliveredEntries.length - 1];
      const fromTimeline = toValidDate(last.timestamp);
      if (fromTimeline) return fromTimeline;
    }
  }
  return toValidDate(row.updatedAt);
}

/** Calendar Y/M/D in Africa/Lagos via formatToParts (locale-independent). */
function lagosYmdParts(d: Date): { year: number; month: number; day: number } {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: EARNINGS_TIMEZONE,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(d);
  const get = (type: Intl.DateTimeFormatPartTypes) => {
    const raw = parts.find((p) => p.type === type)?.value;
    const n = raw ? parseInt(raw, 10) : NaN;
    if (!Number.isFinite(n)) {
      throw new Error(`Could not resolve ${type} in ${EARNINGS_TIMEZONE}`);
    }
    return n;
  };
  return { year: get("year"), month: get("month"), day: get("day") };
}

function dateKeyInLagos(d: Date): string {
  const { year, month, day } = lagosYmdParts(d);
  return `${year}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
}

function dayLabelInLagos(d: Date): string {
  const weekday = new Intl.DateTimeFormat("en-US", {
    timeZone: EARNINGS_TIMEZONE,
    weekday: "short",
  }).format(d);
  const { day } = lagosYmdParts(d);
  return `${weekday} ${day}`;
}

function lastNDayBucketsInLagos(n: number): { date: string; label: string }[] {
  const today = lagosYmdParts(new Date());
  const out: { date: string; label: string }[] = [];
  for (let i = n - 1; i >= 0; i--) {
    // Noon UTC keeps the calendar day stable for Africa/Lagos (UTC+1, no DST).
    const utc = new Date(Date.UTC(today.year, today.month - 1, today.day - i, 12, 0, 0));
    if (!isValidDate(utc)) {
      throw new Error("Failed to build earnings day bucket");
    }
    out.push({
      date: dateKeyInLagos(utc),
      label: dayLabelInLagos(utc),
    });
  }
  return out;
}

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
   * Nearest on-duty rider within maxDistanceMeters (MongoDB returns candidates sorted by distance).
   * Does not mutate isAvailable — riders may hold multiple concurrent offers/jobs while on duty.
   */
  private async findNearestOnDutyRiderInRadius(
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
    return Rider.findOne(geoFilter).exec();
  }

  /**
   * Finds nearest active, verified, on-duty rider with a GeoJSON location; tries 5 km then 10 km.
   * @param excludeRiderIds riders to skip (e.g. already declined this shipment)
   */
  async findNearestOnDutyRider(
    longitude: number,
    latitude: number,
    excludeRiderIds: Types.ObjectId[] = []
  ): Promise<IRider | null> {
    let rider = await this.findNearestOnDutyRiderInRadius(
      longitude,
      latitude,
      NEAR_METERS_PRIMARY,
      excludeRiderIds
    );
    if (!rider) {
      rider = await this.findNearestOnDutyRiderInRadius(
        longitude,
        latitude,
        NEAR_METERS_FALLBACK,
        excludeRiderIds
      );
    }
    return rider;
  }

  /** @deprecated Use findNearestOnDutyRider */
  async claimNearestAvailableRider(
    longitude: number,
    latitude: number,
    excludeRiderIds: Types.ObjectId[] = []
  ): Promise<IRider | null> {
    return this.findNearestOnDutyRider(longitude, latitude, excludeRiderIds);
  }

  async updateLocationByUserId(userId: string, longitude: number, latitude: number): Promise<IRider | null> {
    const location: IRiderLocation = {
      type: "Point",
      coordinates: [longitude, latitude],
    };
    const updated = await Rider.findOneAndUpdate(
      { userId },
      { $set: { location } },
      { new: true, runValidators: true }
    )
      .populate("userId", "firstName lastName email phone")
      .exec();

    if (updated?._id) {
      const riderMongoId = updated._id as Types.ObjectId;
      const trackingStatuses = [
        ShipmentStatus.AWAITING_RIDER_RESPONSE,
        ShipmentStatus.RIDER_ASSIGNED,
        ShipmentStatus.PICKED_UP,
        ShipmentStatus.IN_TRANSIT,
      ];
      try {
        const rows = await Shipment.find({
          riderID: riderMongoId,
          status: { $in: trackingStatuses },
        })
          .select("userId")
          .lean()
          .exec();
        for (const row of rows) {
          broadcastToUser(String(row.userId), {
            event: "rider_location",
            shipmentId: String(row._id),
            longitude,
            latitude,
          });
        }
      } catch (e) {
        logger.warn("Failed to broadcast rider location to shipment owners", {
          message: e instanceof Error ? e.message : String(e),
        });
      }
    }

    return updated;
  }

  async findByUserId(userId: string): Promise<IRider | null> {
    return Rider.findOne({ userId }).populate("userId", "firstName lastName email phone").exec();
  }

  async updateAvailabilityByUserId(userId: string, isAvailable: boolean): Promise<IRider | null> {
    const rider = await Rider.findOne({ userId }).exec();
    if (!rider) return null;

    if (isAvailable) {
      if (rider.status !== RiderStatus.ACTIVE) {
        throw new Error("Your account must be active before you can go available for new jobs.");
      }
      if (!rider.isVerified) {
        throw new Error("Your rider profile must be verified before you can go available for new jobs.");
      }
    }

    return Rider.findOneAndUpdate(
      { userId },
      { $set: { isAvailable } },
      { new: true, runValidators: true }
    )
      .populate("userId", "firstName lastName email phone")
      .exec();
  }

  async setRiderAvailable(riderId: string, available: boolean): Promise<void> {
    await Rider.findByIdAndUpdate(riderId, { $set: { isAvailable: available } }, { runValidators: true }).exec();
  }

  /**
   * On-duty rider by id (active, verified, isAvailable). Does not change isAvailable.
   */
  async findOnDutyRiderById(riderId: string): Promise<IRider | null> {
    if (!Types.ObjectId.isValid(riderId)) return null;
    return Rider.findOne({
      _id: riderId,
      status: RiderStatus.ACTIVE,
      isVerified: true,
      isAvailable: true,
    })
      .populate("userId", "firstName lastName email phone")
      .exec();
  }

  /** @deprecated Use findOnDutyRiderById */
  async claimRiderById(riderId: string): Promise<IRider | null> {
    return this.findOnDutyRiderById(riderId);
  }

  async listAvailableRiders(): Promise<IRider[]> {
    return Rider.find({
      status: RiderStatus.ACTIVE,
      isVerified: true,
      isAvailable: true,
    })
      .populate("userId", "firstName lastName email phone")
      .sort({ updatedAt: -1 })
      .exec();
  }

  /**
   * Daily and all-time earnings for the authenticated rider.
   * Each delivered shipment credited to this rider (current riderID) earns a fixed rate.
   */
  async getEarningsForUser(userId: string, days = 7): Promise<RiderEarningsSummary | null> {
    const rider = await Rider.findOne({ userId }).select("_id").lean().exec();
    if (!rider?._id) return null;

    const dayCount = Math.min(Math.max(Math.floor(days) || 7, 1), 31);
    const buckets = lastNDayBucketsInLagos(dayCount);
    const dayIndex = new Map(buckets.map((b, i) => [b.date, i]));
    const counts = new Array(dayCount).fill(0);

    const rows = (await Shipment.find({
      riderID: rider._id,
      status: ShipmentStatus.DELIVERED,
    })
      .select("timeline updatedAt")
      .lean()
      .exec()) as LeanDeliveredShipment[];

    for (const row of rows) {
      const deliveredAt = deliveredAtFromDoc(row);
      if (!deliveredAt) continue;
      const key = dateKeyInLagos(deliveredAt);
      const idx = dayIndex.get(key);
      if (idx !== undefined) counts[idx] += 1;
    }

    const daily: RiderDailyEarningsBucket[] = buckets.map((b, i) => ({
      date: b.date,
      label: b.label,
      deliveredCount: counts[i],
      earningsNgn: counts[i] * RIDER_EARNINGS_PER_DELIVERY_NGN,
    }));

    const periodDeliveredCount = counts.reduce((a: number, b: number) => a + b, 0);
    const allTimeDeliveredCount = rows.length;

    return {
      ratePerDelivery: RIDER_EARNINGS_PER_DELIVERY_NGN,
      days: dayCount,
      timezone: EARNINGS_TIMEZONE,
      daily,
      periodDeliveredCount,
      periodEarningsNgn: periodDeliveredCount * RIDER_EARNINGS_PER_DELIVERY_NGN,
      allTimeDeliveredCount,
      allTimeEarningsNgn: allTimeDeliveredCount * RIDER_EARNINGS_PER_DELIVERY_NGN,
    };
  }
}
