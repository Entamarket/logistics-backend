import { Types } from "mongoose";
import { Shipment } from "../../shared/models/Shipment";
import { Rider, IRider } from "../../shared/models/Rider";
import { User, IUser } from "../../shared/models/User";
import { Feedback } from "../../shared/models/Feedback";
import { RiderStatus, ShipmentStatus, UserAccountStatus } from "../../shared/lib/enums";
import { RiderService } from "../rider/rider.service";
import { ShipmentService, CreateShipmentBody } from "../shipment/shipment.service";

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

export interface MonthlyFinancialReportDto {
  yearMonth: string;
  label: string;
  revenue: number;
  deliveredCount: number;
  averageOrderValue: number;
  changeFromPreviousPct: number | null;
}

export interface FinancialReportsDto {
  currency: "NGN";
  generatedAt: string;
  monthCount: number;
  /** Set when the report is scoped to a calendar year (`?year=`). */
  year?: number;
  availableYears: number[];
  allTimeRevenue: number;
  allTimeDeliveredCount: number;
  periodTotalRevenue: number;
  periodTotalDelivered: number;
  periodAverageMonthlyRevenue: number;
  monthly: MonthlyFinancialReportDto[];
}

export interface GetFinancialReportsOptions {
  year?: number;
  monthCount?: number;
}

export interface MonthlyFinancialDeliveryDto {
  id: string;
  price: number;
  paymentStatus: string;
  deliveryType: string;
  deliveredAt: string;
  createdAt: string;
  senderName: string;
  recipientName: string;
  client: { id: string; firstName: string; lastName: string; email: string };
  rider: AdminRiderDto | null;
}

export interface MonthlyFinancialReportDetailDto {
  yearMonth: string;
  label: string;
  revenue: number;
  deliveredCount: number;
  averageOrderValue: number;
  deliveries: MonthlyFinancialDeliveryDto[];
}

export interface AdminClientDto {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  phone: string;
}

export interface AdminRiderDto {
  riderId: string;
  firstName: string;
  lastName: string;
  email: string;
  phone: string;
}

export interface AdminBulkShipmentResult {
  index: number;
  success: boolean;
  shipmentId?: string;
  error?: string;
}

export interface AdminShipmentListItem {
  id: string;
  status: string;
  deliveryType: string;
  price: number;
  paymentStatus: string;
  createdAt: string;
  client: AdminClientDto;
  rider: AdminRiderDto | null;
  assignmentLabel: string;
}

export interface AdminShipmentDetail extends AdminShipmentListItem {
  senderDetails: {
    fullName: string;
    address: string;
    phone: string;
    country?: string;
    state?: string;
  };
  recipientDetails: {
    fullName: string;
    address: string;
    phone: string;
    country?: string;
    state?: string;
  };
  packageDetails: {
    type: string;
    weight: number;
    lengthCm: number;
    widthCm: number;
    heightCm: number;
    quantity: number;
    note?: string;
  };
  timeline: { status: string; timestamp: string }[];
  pickupWindowStart?: string;
  pickupWindowEnd?: string;
  pickupLongitude?: number;
  pickupLatitude?: number;
  recipientLongitude?: number;
  recipientLatitude?: number;
  riderResponseDeadline?: string;
  declinedRiderCount: number;
  updatedAt: string;
}

export interface ListShipmentsQuery {
  status?: string;
  limit?: number;
}

export interface AdminClientListItem {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  phone: string;
  status: string;
  isEmailVerified: boolean;
  createdAt: string;
  shipmentCount: number;
}

export interface AdminClientStats {
  totalShipments: number;
  activeShipments: number;
  deliveredCount: number;
  totalSpent: number;
}

export interface AdminClientDetail extends AdminClientListItem {
  stats: AdminClientStats;
}

export interface AdminClientActivityShipment {
  id: string;
  status: string;
  deliveryType: string;
  price: number;
  paymentStatus: string;
  createdAt: string;
  recipientName: string;
}

export interface AdminClientActivityFeedback {
  id: string;
  shipmentId: string;
  rating: number;
  comment: string;
  createdAt: string;
}

export interface AdminClientActivity {
  shipments: AdminClientActivityShipment[];
  feedback: AdminClientActivityFeedback[];
}

export interface ListClientsQuery {
  q?: string;
  limit?: number;
}

export interface RiderMonthlyPerformance {
  yearMonth: string;
  label: string;
  completedCount: number;
}

export interface RiderCompletedOrder {
  id: string;
  status: string;
  deliveryType: string;
  price: number;
  paymentStatus: string;
  deliveredAt: string;
  createdAt: string;
  senderName: string;
  recipientName: string;
  client: { id: string; firstName: string; lastName: string; email: string };
}

export interface RiderPerformanceDto {
  riderId: string;
  totalCompleted: number;
  monthly: RiderMonthlyPerformance[];
  orders: RiderCompletedOrder[];
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

type ClientUserFields = {
  _id: Types.ObjectId;
  firstName: string;
  lastName: string;
  email: string;
  phone: string;
  status?: string;
  isEmailVerified: boolean;
  createdAt: Date;
  shipmentCount?: number;
};

function mapUserToListItem(user: ClientUserFields): AdminClientListItem {
  return {
    id: user._id.toString(),
    firstName: user.firstName,
    lastName: user.lastName,
    email: user.email,
    phone: user.phone,
    status: user.status || UserAccountStatus.ACTIVE,
    isEmailVerified: user.isEmailVerified,
    createdAt: new Date(user.createdAt).toISOString(),
    shipmentCount: user.shipmentCount ?? 0,
  };
}

type PopulatedUser = {
  _id: Types.ObjectId;
  firstName: string;
  lastName: string;
  email: string;
  phone: string;
};

type PopulatedRider = {
  _id: Types.ObjectId;
  userId: PopulatedUser | Types.ObjectId;
};

type PopulatedShipmentDoc = {
  _id: Types.ObjectId;
  userId: PopulatedUser | Types.ObjectId;
  status: string;
  deliveryType: string;
  price: number;
  paymentStatus: string;
  riderID?: PopulatedRider | Types.ObjectId | null;
  senderDetails: AdminShipmentDetail["senderDetails"];
  recipientDetails: AdminShipmentDetail["recipientDetails"];
  packageDetails: AdminShipmentDetail["packageDetails"];
  timeline?: { status: string; timestamp?: Date }[];
  pickupWindowStart?: Date;
  pickupWindowEnd?: Date;
  pickupLongitude?: number;
  pickupLatitude?: number;
  recipientLongitude?: number;
  recipientLatitude?: number;
  riderResponseDeadline?: Date;
  declinedRiderIds?: Types.ObjectId[];
  createdAt: Date;
  updatedAt: Date;
};

const shipmentPopulate = [
  { path: "userId", select: "firstName lastName email phone" },
  {
    path: "riderID",
    populate: { path: "userId", select: "firstName lastName email phone" },
  },
];

function isPopulatedUser(v: unknown): v is PopulatedUser {
  return v != null && typeof v === "object" && "firstName" in v && "email" in v;
}

function isPopulatedRider(v: PopulatedRider | Types.ObjectId | null | undefined): v is PopulatedRider {
  return v != null && typeof v === "object" && "userId" in v;
}

function mapClient(userId: PopulatedUser | Types.ObjectId): AdminClientDto {
  if (!isPopulatedUser(userId)) {
    const id = userId.toString();
    return { id, firstName: "", lastName: "", email: "", phone: "" };
  }
  return {
    id: userId._id.toString(),
    firstName: userId.firstName,
    lastName: userId.lastName,
    email: userId.email,
    phone: userId.phone,
  };
}

function mapRider(riderID: PopulatedRider | Types.ObjectId | null | undefined): AdminRiderDto | null {
  if (!riderID || !isPopulatedRider(riderID)) return null;
  const user = riderID.userId;
  if (!isPopulatedUser(user)) return null;
  return {
    riderId: riderID._id.toString(),
    firstName: user.firstName,
    lastName: user.lastName,
    email: user.email,
    phone: user.phone,
  };
}

function mapRiderDocToDto(rider: IRider): AdminRiderDto | null {
  const user = rider.userId;
  if (!isPopulatedUser(user)) return null;
  const u = user;
  return {
    riderId: (rider._id as Types.ObjectId).toString(),
    firstName: u.firstName,
    lastName: u.lastName,
    email: u.email,
    phone: u.phone,
  };
}

function assignmentLabel(status: string, rider: AdminRiderDto | null): string {
  if (!rider) {
    if (status === ShipmentStatus.SEARCHING_RIDER) return "Searching for rider";
    return "Unassigned";
  }
  if (status === ShipmentStatus.AWAITING_RIDER_RESPONSE) return "Offer pending";
  if (
    status === ShipmentStatus.RIDER_ASSIGNED ||
    status === ShipmentStatus.PICKED_UP ||
    status === ShipmentStatus.IN_TRANSIT
  ) {
    return "Assigned";
  }
  if (status === ShipmentStatus.DELIVERED) return "Delivered";
  if (status === ShipmentStatus.CANCELLED) return "Cancelled";
  return "Assigned";
}

function toIso(d: Date | undefined): string | undefined {
  return d ? new Date(d).toISOString() : undefined;
}

function mapListItem(doc: PopulatedShipmentDoc): AdminShipmentListItem {
  const client = mapClient(doc.userId);
  const rider = mapRider(doc.riderID);
  return {
    id: doc._id.toString(),
    status: doc.status,
    deliveryType: doc.deliveryType,
    price: doc.price,
    paymentStatus: doc.paymentStatus,
    createdAt: new Date(doc.createdAt).toISOString(),
    client,
    rider,
    assignmentLabel: assignmentLabel(doc.status, rider),
  };
}

function mapDetail(doc: PopulatedShipmentDoc): AdminShipmentDetail {
  const base = mapListItem(doc);
  const timeline = (doc.timeline ?? []).map((e) => ({
    status: e.status,
    timestamp: e.timestamp ? new Date(e.timestamp).toISOString() : new Date().toISOString(),
  }));
  return {
    ...base,
    senderDetails: doc.senderDetails,
    recipientDetails: doc.recipientDetails,
    packageDetails: doc.packageDetails,
    timeline,
    pickupWindowStart: toIso(doc.pickupWindowStart),
    pickupWindowEnd: toIso(doc.pickupWindowEnd),
    pickupLongitude: doc.pickupLongitude,
    pickupLatitude: doc.pickupLatitude,
    recipientLongitude: doc.recipientLongitude,
    recipientLatitude: doc.recipientLatitude,
    riderResponseDeadline: toIso(doc.riderResponseDeadline),
    declinedRiderCount: doc.declinedRiderIds?.length ?? 0,
    updatedAt: new Date(doc.updatedAt).toISOString(),
  };
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

const YEAR_MONTH_RE = /^(\d{4})-(\d{2})$/;

export function parseYearMonth(value: string): { year: number; month: number } | null {
  const m = YEAR_MONTH_RE.exec(value.trim());
  if (!m) return null;
  const year = parseInt(m[1], 10);
  const month = parseInt(m[2], 10);
  if (month < 1 || month > 12) return null;
  return { year, month };
}

export class AdminService {
  private riderService = new RiderService();
  private shipmentService = new ShipmentService();

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

  /**
   * Monthly financial report: revenue and delivery counts per calendar month.
   * Pass `year` for Jan–Dec of a calendar year, or `monthCount` for a rolling window.
   */
  async getFinancialReports(options: GetFinancialReportsOptions = {}): Promise<FinancialReportsDto> {
    const rows = (await Shipment.find({ status: ShipmentStatus.DELIVERED })
      .select("price timeline updatedAt")
      .lean()
      .exec()) as LeanShipment[];

    let allTimeRevenue = 0;
    const revenueByMonth = new Map<string, number>();
    const countByMonth = new Map<string, number>();
    const yearsSet = new Set<number>();

    const now = new Date();
    yearsSet.add(now.getFullYear());

    for (const row of rows) {
      const price = typeof row.price === "number" && !Number.isNaN(row.price) ? row.price : 0;
      allTimeRevenue += price;
      const t = deliveredAtFromDoc(row);
      yearsSet.add(t.getFullYear());
      const key = `${t.getFullYear()}-${String(t.getMonth() + 1).padStart(2, "0")}`;
      revenueByMonth.set(key, (revenueByMonth.get(key) || 0) + price);
      countByMonth.set(key, (countByMonth.get(key) || 0) + 1);
    }

    const availableYears = [...yearsSet].sort((a, b) => b - a);

    const monthly: MonthlyFinancialReportDto[] = [];
    let periodTotalRevenue = 0;
    let periodTotalDelivered = 0;
    let previousRevenue: number | null = null;

    const buildMonthEntry = (d: Date): MonthlyFinancialReportDto => {
      const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
      const label = d.toLocaleString(undefined, { month: "long", year: "numeric" });
      const revenue = revenueByMonth.get(key) || 0;
      const deliveredCount = countByMonth.get(key) || 0;
      const averageOrderValue =
        deliveredCount > 0 ? Math.round(revenue / deliveredCount) : 0;

      let changeFromPreviousPct: number | null = null;
      if (previousRevenue !== null) {
        changeFromPreviousPct =
          previousRevenue > 0
            ? Math.round(((revenue - previousRevenue) / previousRevenue) * 100)
            : revenue > 0
              ? 100
              : 0;
      }

      previousRevenue = revenue;
      periodTotalRevenue += revenue;
      periodTotalDelivered += deliveredCount;

      return {
        yearMonth: key,
        label,
        revenue,
        deliveredCount,
        averageOrderValue,
        changeFromPreviousPct,
      };
    };

    if (options.year !== undefined) {
      const calendarYear = options.year;
      previousRevenue = null;
      periodTotalRevenue = 0;
      periodTotalDelivered = 0;

      for (let m = 0; m < 12; m++) {
        monthly.push(buildMonthEntry(new Date(calendarYear, m, 1)));
      }

      return {
        currency: "NGN",
        generatedAt: new Date().toISOString(),
        monthCount: 12,
        year: calendarYear,
        availableYears,
        allTimeRevenue,
        allTimeDeliveredCount: rows.length,
        periodTotalRevenue,
        periodTotalDelivered,
        periodAverageMonthlyRevenue: Math.round(periodTotalRevenue / 12),
        monthly,
      };
    }

    const monthCount = options.monthCount ?? 12;
    previousRevenue = null;
    periodTotalRevenue = 0;
    periodTotalDelivered = 0;

    for (let i = monthCount - 1; i >= 0; i--) {
      monthly.push(buildMonthEntry(new Date(now.getFullYear(), now.getMonth() - i, 1)));
    }

    return {
      currency: "NGN",
      generatedAt: new Date().toISOString(),
      monthCount,
      availableYears,
      allTimeRevenue,
      allTimeDeliveredCount: rows.length,
      periodTotalRevenue,
      periodTotalDelivered,
      periodAverageMonthlyRevenue:
        monthCount > 0 ? Math.round(periodTotalRevenue / monthCount) : 0,
      monthly,
    };
  }

  /**
   * Delivered shipments for a single calendar month (same delivery-date bucketing as getFinancialReports).
   */
  async getFinancialReportMonth(yearMonth: string): Promise<MonthlyFinancialReportDetailDto | null> {
    const parsed = parseYearMonth(yearMonth);
    if (!parsed) return null;

    const { year, month } = parsed;
    const labelDate = new Date(year, month - 1, 1);
    const label = labelDate.toLocaleString(undefined, { month: "long", year: "numeric" });

    const rows = (await Shipment.find({ status: ShipmentStatus.DELIVERED })
      .select("price paymentStatus deliveryType timeline updatedAt createdAt senderDetails recipientDetails userId riderID")
      .populate(shipmentPopulate)
      .lean()
      .exec()) as unknown as PopulatedShipmentDoc[];

    const deliveries: MonthlyFinancialDeliveryDto[] = [];

    for (const row of rows) {
      const deliveredAt = deliveredAtFromDoc(row as LeanShipment);
      const key = `${deliveredAt.getFullYear()}-${String(deliveredAt.getMonth() + 1).padStart(2, "0")}`;
      if (key !== yearMonth) continue;

      const user = row.userId;
      let client = { id: "", firstName: "", lastName: "", email: "" };
      if (isPopulatedUser(user)) {
        client = {
          id: user._id.toString(),
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
        };
      } else if (user) {
        client = { id: String(user), firstName: "", lastName: "", email: "" };
      }

      const price = typeof row.price === "number" && !Number.isNaN(row.price) ? row.price : 0;

      deliveries.push({
        id: row._id.toString(),
        price,
        paymentStatus: row.paymentStatus,
        deliveryType: row.deliveryType,
        deliveredAt: deliveredAt.toISOString(),
        createdAt: new Date(row.createdAt).toISOString(),
        senderName: row.senderDetails?.fullName ?? "—",
        recipientName: row.recipientDetails?.fullName ?? "—",
        client,
        rider: mapRider(row.riderID),
      });
    }

    deliveries.sort((a, b) => new Date(b.deliveredAt).getTime() - new Date(a.deliveredAt).getTime());

    const revenue = deliveries.reduce((sum, d) => sum + d.price, 0);
    const deliveredCount = deliveries.length;
    const averageOrderValue = deliveredCount > 0 ? Math.round(revenue / deliveredCount) : 0;

    return {
      yearMonth,
      label,
      revenue,
      deliveredCount,
      averageOrderValue,
      deliveries,
    };
  }

  async listShipments(query: ListShipmentsQuery = {}): Promise<AdminShipmentListItem[]> {
    const limit = Math.min(Math.max(query.limit ?? 100, 1), 200);
    const filter: Record<string, unknown> = {};
    if (query.status) {
      filter.status = query.status;
    }

    const rows = (await Shipment.find(filter)
      .sort({ createdAt: -1 })
      .limit(limit)
      .populate(shipmentPopulate)
      .lean()
      .exec()) as unknown as PopulatedShipmentDoc[];

    return rows.map(mapListItem);
  }

  async getShipmentById(id: string): Promise<AdminShipmentDetail | null> {
    if (!Types.ObjectId.isValid(id)) return null;
    const doc = (await Shipment.findById(id)
      .populate(shipmentPopulate)
      .lean()
      .exec()) as PopulatedShipmentDoc | null;
    if (!doc) return null;
    return mapDetail(doc);
  }

  async listAvailableRiders(): Promise<AdminRiderDto[]> {
    const rows = await this.riderService.listAvailableRiders();
    const dtos: AdminRiderDto[] = [];
    for (const row of rows) {
      const dto = mapRiderDocToDto(row);
      if (dto) dtos.push(dto);
    }
    return dtos;
  }

  async assignShipmentToRider(shipmentId: string, riderId: string): Promise<AdminShipmentDetail> {
    await this.shipmentService.adminAssignRider(shipmentId, riderId);
    const detail = await this.getShipmentById(shipmentId);
    if (!detail) {
      throw new Error("Shipment not found after assignment");
    }
    return detail;
  }

  async bulkCreateShipmentsAndAssign(params: {
    clientId: string;
    defaultRiderId: string;
    shipments: Array<CreateShipmentBody & { riderId?: string }>;
  }): Promise<AdminBulkShipmentResult[]> {
    const { clientId, defaultRiderId, shipments } = params;
    const client = await this.findClientById(clientId);
    if (!client) {
      throw new Error("Client not found");
    }
    const clientStatus = client.status || UserAccountStatus.ACTIVE;
    if (clientStatus !== UserAccountStatus.ACTIVE) {
      throw new Error("This client account cannot create shipments.");
    }

    const results: AdminBulkShipmentResult[] = [];
    for (let index = 0; index < shipments.length; index++) {
      const item = shipments[index];
      const riderId = (item.riderId?.trim() || defaultRiderId).trim();
      if (!riderId) {
        results.push({ index, success: false, error: "Rider is required for this shipment" });
        continue;
      }
      try {
        const { riderId: _override, ...shipmentData } = item;
        const created = await this.shipmentService.createShipmentForAdmin(clientId, shipmentData);
        await this.shipmentService.adminAssignRider(created._id.toString(), riderId);
        results.push({ index, success: true, shipmentId: created._id.toString() });
      } catch (e) {
        const message = e instanceof Error ? e.message : "Failed to create or assign shipment";
        results.push({ index, success: false, error: message });
      }
    }
    return results;
  }

  private async findClientById(id: string): Promise<IUser | null> {
    if (!Types.ObjectId.isValid(id)) return null;
    const user = await User.findOne({ _id: id, role: "client" })
      .select("-password")
      .exec();
    return user;
  }

  private async getClientStats(userId: Types.ObjectId): Promise<AdminClientStats> {
    const uid = userId;
    const [totalShipments, activeShipments, deliveredCount, deliveredRows] = await Promise.all([
      Shipment.countDocuments({ userId: uid }).exec(),
      Shipment.countDocuments({
        userId: uid,
        status: { $nin: [ShipmentStatus.DELIVERED, ShipmentStatus.CANCELLED] },
      }).exec(),
      Shipment.countDocuments({ userId: uid, status: ShipmentStatus.DELIVERED }).exec(),
      Shipment.find({ userId: uid, status: ShipmentStatus.DELIVERED }).select("price").lean().exec(),
    ]);
    let totalSpent = 0;
    for (const row of deliveredRows) {
      const price = typeof row.price === "number" && !Number.isNaN(row.price) ? row.price : 0;
      totalSpent += price;
    }
    return { totalShipments, activeShipments, deliveredCount, totalSpent };
  }

  async listClients(query: ListClientsQuery = {}): Promise<AdminClientListItem[]> {
    const limit = Math.min(Math.max(query.limit ?? 50, 1), 100);
    const match: Record<string, unknown> = { role: "client" };
    const q = query.q?.trim();
    if (q) {
      const pattern = escapeRegex(q);
      const regex = new RegExp(pattern, "i");
      match.$or = [{ firstName: regex }, { lastName: regex }, { email: regex }, { phone: regex }];
    }

    const rows = await User.aggregate([
      { $match: match },
      {
        $lookup: {
          from: "shipments",
          localField: "_id",
          foreignField: "userId",
          as: "_shipments",
        },
      },
      { $addFields: { shipmentCount: { $size: "$_shipments" } } },
      { $project: { password: 0, _shipments: 0 } },
      { $sort: { createdAt: -1 } },
      { $limit: limit },
    ]).exec();

    return rows.map((row) => mapUserToListItem(row as ClientUserFields & { shipmentCount: number }));
  }

  async getClientById(id: string): Promise<AdminClientDetail | null> {
    const user = await this.findClientById(id);
    if (!user) return null;
    const stats = await this.getClientStats(user._id as Types.ObjectId);
    const shipmentCount = stats.totalShipments;
    const plain = user.toObject() as ClientUserFields;
    return { ...mapUserToListItem({ ...plain, shipmentCount }), stats };
  }

  async getClientActivity(id: string): Promise<AdminClientActivity | null> {
    if (!Types.ObjectId.isValid(id)) return null;
    const userExists = await User.exists({ _id: id, role: "client" }).exec();
    if (!userExists) return null;

    const userObjectId = new Types.ObjectId(id);
    const [shipments, feedbackRows] = await Promise.all([
      Shipment.find({ userId: userObjectId })
        .sort({ createdAt: -1 })
        .limit(50)
        .select("status deliveryType price paymentStatus createdAt recipientDetails")
        .lean()
        .exec(),
      Feedback.find({ clientUserId: userObjectId })
        .sort({ createdAt: -1 })
        .limit(50)
        .lean()
        .exec(),
    ]);

    return {
      shipments: shipments.map((s) => ({
        id: String(s._id),
        status: s.status,
        deliveryType: s.deliveryType,
        price: s.price,
        paymentStatus: s.paymentStatus,
        createdAt: new Date(s.createdAt).toISOString(),
        recipientName: s.recipientDetails?.fullName ?? "—",
      })),
      feedback: feedbackRows.map((f) => ({
        id: String(f._id),
        shipmentId: String(f.shipmentId),
        rating: f.rating,
        comment: f.comment ?? "",
        createdAt: new Date(f.createdAt).toISOString(),
      })),
    };
  }

  async updateClientStatus(
    id: string,
    status: "active" | "suspended" | "blocked"
  ): Promise<AdminClientDetail> {
    if (
      status !== UserAccountStatus.ACTIVE &&
      status !== UserAccountStatus.SUSPENDED &&
      status !== UserAccountStatus.BLOCKED
    ) {
      throw new Error("status must be 'active', 'suspended', or 'blocked'");
    }
    const user = await User.findOneAndUpdate(
      { _id: id, role: "client" },
      { $set: { status } },
      { new: true, runValidators: true }
    )
      .select("-password")
      .exec();
    if (!user) {
      throw new Error("Client not found");
    }
    const stats = await this.getClientStats(user._id as Types.ObjectId);
    const plain = user.toObject() as ClientUserFields;
    return {
      ...mapUserToListItem({ ...plain, shipmentCount: stats.totalShipments }),
      stats,
    };
  }

  async getRiderPerformance(riderId: string, monthCount: number): Promise<RiderPerformanceDto | null> {
    if (!Types.ObjectId.isValid(riderId)) return null;
    const riderExists = await Rider.exists({ _id: riderId }).exec();
    if (!riderExists) return null;

    const riderObjectId = new Types.ObjectId(riderId);
    const rows = await Shipment.find({
      riderID: riderObjectId,
      status: ShipmentStatus.DELIVERED,
    })
      .populate("userId", "firstName lastName email")
      .sort({ updatedAt: -1 })
      .lean()
      .exec();

    const byMonth = new Map<string, number>();
    const orders: RiderCompletedOrder[] = [];

    for (const row of rows) {
      const deliveredAt = deliveredAtFromDoc(row as LeanShipment);
      const key = `${deliveredAt.getFullYear()}-${String(deliveredAt.getMonth() + 1).padStart(2, "0")}`;
      byMonth.set(key, (byMonth.get(key) || 0) + 1);

      const user = row.userId;
      let client = { id: "", firstName: "", lastName: "", email: "" };
      if (isPopulatedUser(user)) {
        client = {
          id: user._id.toString(),
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
        };
      } else if (user) {
        client = { id: String(user), firstName: "", lastName: "", email: "" };
      }

      orders.push({
        id: String(row._id),
        status: row.status,
        deliveryType: row.deliveryType,
        price: row.price,
        paymentStatus: row.paymentStatus,
        deliveredAt: deliveredAt.toISOString(),
        createdAt: new Date(row.createdAt).toISOString(),
        senderName: row.senderDetails?.fullName ?? "—",
        recipientName: row.recipientDetails?.fullName ?? "—",
        client,
      });
    }

    const now = new Date();
    const monthly: RiderMonthlyPerformance[] = [];
    for (let i = monthCount - 1; i >= 0; i--) {
      const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
      const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
      const label = d.toLocaleString(undefined, { month: "short", year: "2-digit" });
      monthly.push({
        yearMonth: key,
        label,
        completedCount: byMonth.get(key) || 0,
      });
    }

    return {
      riderId,
      totalCompleted: orders.length,
      monthly,
      orders,
    };
  }
}
