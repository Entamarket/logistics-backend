import { Shipment } from "../../shared/models/Shipment";
import { Rider } from "../../shared/models/Rider";
import { RiderStatus, ShipmentStatus } from "../../shared/lib/enums";

export interface MonthlyRevenueDto {
  yearMonth: string;
  label: string;
  amount: number;
}

export interface RevenueSummaryDto {
  currency: "NGN";
  /** Sum of shipment `price` for every delivered shipment (all time). */
  totalEarned: number;
  deliveredCount: number;
  /** Shipments still in progress / not closed (not delivered and not cancelled). */
  activeShipmentCount: number;
  /** Riders active, verified, and marked available for dispatch. */
  availableRidersCount: number;
  /** Last `monthCount` calendar months, including zeros. */
  monthly: MonthlyRevenueDto[];
}

type LeanShipment = {
  price?: number;
  timeline?: { status: string; timestamp?: Date }[];
  updatedAt?: Date;
};

function deliveredAtFromDoc(row: LeanShipment): Date {
  const tl = row.timeline;
  if (tl?.length) {
    const deliveredEntries = tl.filter((e) => e.status === ShipmentStatus.DELIVERED);
    if (deliveredEntries.length) {
      const last = deliveredEntries[deliveredEntries.length - 1];
      if (last.timestamp) return new Date(last.timestamp);
    }
  }
  return row.updatedAt ? new Date(row.updatedAt) : new Date();
}

export class AdminService {
  /**
   * Platform revenue from completed deliveries: sum of `price` on delivered shipments.
   * Monthly series covers the last `monthCount` calendar months (amounts only from those months).
   */
  async getRevenueSummary(monthCount: number): Promise<RevenueSummaryDto> {
    const rows = (await Shipment.find({ status: ShipmentStatus.DELIVERED })
      .select("price timeline updatedAt")
      .lean()
      .exec()) as LeanShipment[];

    let totalEarned = 0;
    for (const row of rows) {
      const price = typeof row.price === "number" && !Number.isNaN(row.price) ? row.price : 0;
      totalEarned += price;
    }

    const byMonth = new Map<string, number>();
    for (const row of rows) {
      const price = typeof row.price === "number" && !Number.isNaN(row.price) ? row.price : 0;
      const t = deliveredAtFromDoc(row);
      const key = `${t.getFullYear()}-${String(t.getMonth() + 1).padStart(2, "0")}`;
      byMonth.set(key, (byMonth.get(key) || 0) + price);
    }

    const now = new Date();
    const monthly: MonthlyRevenueDto[] = [];
    for (let i = monthCount - 1; i >= 0; i--) {
      const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
      const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
      const label = d.toLocaleString(undefined, { month: "short", year: "2-digit" });
      monthly.push({
        yearMonth: key,
        label,
        amount: byMonth.get(key) || 0,
      });
    }

    const activeShipmentCount = await Shipment.countDocuments({
      status: { $nin: [ShipmentStatus.DELIVERED, ShipmentStatus.CANCELLED] },
    }).exec();

    const availableRidersCount = await Rider.countDocuments({
      status: RiderStatus.ACTIVE,
      isVerified: true,
      isAvailable: true,
    }).exec();

    return {
      currency: "NGN",
      totalEarned,
      deliveredCount: rows.length,
      activeShipmentCount,
      availableRidersCount,
      monthly,
    };
  }
}
