import { Response } from "express";
import { AuthRequest } from "../../shared/middlewares/auth.middleware";
import { AdminService } from "./admin.service";
import { ComplaintService } from "../complaint/complaint.service";
import { ContactService } from "../contact/contact.service";

const adminService = new AdminService();
const complaintService = new ComplaintService();
const contactService = new ContactService();

export class AdminController {
  async revenueSummary(req: AuthRequest, res: Response): Promise<void> {
    try {
      const raw = typeof req.query.months === "string" ? parseInt(req.query.months, 10) : 12;
      const months = Number.isFinite(raw) ? Math.min(Math.max(raw, 3), 24) : 12;
      const data = await adminService.getRevenueSummary(months);
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching revenue summary";
      res.status(500).json({ success: false, message });
    }
  }

  async financialReports(req: AuthRequest, res: Response): Promise<void> {
    try {
      const rawYear = typeof req.query.year === "string" ? parseInt(req.query.year, 10) : NaN;
      if (Number.isFinite(rawYear)) {
        if (rawYear < 2000 || rawYear > 2100) {
          res.status(400).json({ success: false, message: "year must be between 2000 and 2100" });
          return;
        }
        const data = await adminService.getFinancialReports({ year: rawYear });
        res.status(200).json({ success: true, data });
        return;
      }

      const raw = typeof req.query.months === "string" ? parseInt(req.query.months, 10) : 12;
      const months = Number.isFinite(raw) ? Math.min(Math.max(raw, 3), 36) : 12;
      const data = await adminService.getFinancialReports({ monthCount: months });
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching financial reports";
      res.status(500).json({ success: false, message });
    }
  }

  async financialReportMonth(req: AuthRequest, res: Response): Promise<void> {
    try {
      const yearMonth = typeof req.params.yearMonth === "string" ? req.params.yearMonth.trim() : "";
      if (!yearMonth) {
        res.status(400).json({ success: false, message: "yearMonth is required (YYYY-MM)" });
        return;
      }
      const data = await adminService.getFinancialReportMonth(yearMonth);
      if (!data) {
        res.status(400).json({ success: false, message: "Invalid yearMonth; use YYYY-MM with month 01–12" });
        return;
      }
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : "Error fetching monthly financial report";
      res.status(500).json({ success: false, message });
    }
  }

  async listShipments(req: AuthRequest, res: Response): Promise<void> {
    try {
      const status = typeof req.query.status === "string" ? req.query.status.trim() : undefined;
      const rawLimit =
        typeof req.query.limit === "string" ? parseInt(req.query.limit, 10) : undefined;
      const limit = rawLimit !== undefined && Number.isFinite(rawLimit) ? rawLimit : undefined;
      const data = await adminService.listShipments({ status: status || undefined, limit });
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching shipments";
      res.status(500).json({ success: false, message });
    }
  }

  async exportShipments(req: AuthRequest, res: Response): Promise<void> {
    try {
      const rawYear = typeof req.query.year === "string" ? parseInt(req.query.year, 10) : NaN;
      if (!Number.isFinite(rawYear) || rawYear < 2000 || rawYear > 2100) {
        res.status(400).json({ success: false, message: "year is required and must be between 2000 and 2100" });
        return;
      }

      let month: number | undefined;
      if (typeof req.query.month === "string" && req.query.month.trim() !== "") {
        const rawMonth = parseInt(req.query.month, 10);
        if (!Number.isFinite(rawMonth) || rawMonth < 1 || rawMonth > 12) {
          res.status(400).json({ success: false, message: "month must be between 1 and 12" });
          return;
        }
        month = rawMonth;
      }

      const data = await adminService.exportShipments({ year: rawYear, month });
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error exporting shipments";
      res.status(500).json({ success: false, message });
    }
  }

  async getShipment(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      if (!id) {
        res.status(400).json({ success: false, message: "Shipment id is required" });
        return;
      }
      const data = await adminService.getShipmentById(id);
      if (!data) {
        res.status(404).json({ success: false, message: "Shipment not found" });
        return;
      }
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching shipment";
      res.status(500).json({ success: false, message });
    }
  }

  async listAvailableRiders(_req: AuthRequest, res: Response): Promise<void> {
    try {
      const data = await adminService.listAvailableRiders();
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching available riders";
      res.status(500).json({ success: false, message });
    }
  }

  async bulkCreateShipments(req: AuthRequest, res: Response): Promise<void> {
    try {
      const adminUserId = req.userId;
      if (!adminUserId) {
        res.status(401).json({ success: false, message: "Authentication required" });
        return;
      }
      const { clientId, defaultRiderId, shipments } = req.body as {
        clientId?: string;
        defaultRiderId?: string;
        shipments?: unknown[];
      };
      if (!defaultRiderId || typeof defaultRiderId !== "string") {
        res.status(400).json({ success: false, message: "defaultRiderId is required" });
        return;
      }
      if (!Array.isArray(shipments) || shipments.length === 0) {
        res.status(400).json({ success: false, message: "shipments must be a non-empty array" });
        return;
      }
      if (shipments.length > 20) {
        res.status(400).json({ success: false, message: "Maximum 20 shipments per batch" });
        return;
      }
      const results = await adminService.bulkCreateShipmentsAndAssign({
        adminUserId,
        clientId: typeof clientId === "string" && clientId.trim() ? clientId.trim() : null,
        defaultRiderId: defaultRiderId.trim(),
        shipments: shipments as Array<{
          deliveryType: "instant" | "scheduled";
          pickupDetails?: {
            address: string;
            phone: string;
            country?: string;
            state?: string;
          };
          senderDetails?: {
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
          pickupWindowStart?: string;
          pickupWindowEnd?: string;
          pickupLongitude?: number;
          pickupLatitude?: number;
          recipientLongitude?: number;
          recipientLatitude?: number;
          riderId?: string;
        }>,
      });
      const succeeded = results.filter((r) => r.success).length;
      res.status(200).json({
        success: true,
        message: `${succeeded} of ${results.length} shipment(s) created and assigned`,
        data: { results },
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error creating shipments";
      const status =
        message.includes("not found") || message.includes("cannot create")
          ? 400
          : 500;
      res.status(status).json({ success: false, message });
    }
  }

  async assignShipment(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const { riderId } = req.body as { riderId?: string };
      if (!id) {
        res.status(400).json({ success: false, message: "Shipment id is required" });
        return;
      }
      if (!riderId || typeof riderId !== "string") {
        res.status(400).json({ success: false, message: "riderId is required" });
        return;
      }
      const data = await adminService.assignShipmentToRider(id, riderId.trim());
      res.status(200).json({
        success: true,
        message: "Rider assigned; awaiting rider acceptance",
        data,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error assigning rider";
      const status = message.includes("not found")
        ? 404
        : message.includes("cannot be assigned") || message.includes("not available")
          ? 400
          : 500;
      res.status(status).json({ success: false, message });
    }
  }

  async listClients(req: AuthRequest, res: Response): Promise<void> {
    try {
      const q = typeof req.query.q === "string" ? req.query.q.trim() : undefined;
      const rawLimit =
        typeof req.query.limit === "string" ? parseInt(req.query.limit, 10) : undefined;
      const limit = rawLimit !== undefined && Number.isFinite(rawLimit) ? rawLimit : undefined;
      const data = await adminService.listClients({ q: q || undefined, limit });
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching clients";
      res.status(500).json({ success: false, message });
    }
  }

  async getClient(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      if (!id) {
        res.status(400).json({ success: false, message: "Client id is required" });
        return;
      }
      const data = await adminService.getClientById(id);
      if (!data) {
        res.status(404).json({ success: false, message: "Client not found" });
        return;
      }
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching client";
      res.status(500).json({ success: false, message });
    }
  }

  async getClientActivity(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      if (!id) {
        res.status(400).json({ success: false, message: "Client id is required" });
        return;
      }
      const data = await adminService.getClientActivity(id);
      if (!data) {
        res.status(404).json({ success: false, message: "Client not found" });
        return;
      }
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching client activity";
      res.status(500).json({ success: false, message });
    }
  }

  async updateClientStatus(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const { status } = req.body as { status?: string };
      if (!id) {
        res.status(400).json({ success: false, message: "Client id is required" });
        return;
      }
      if (status !== "active" && status !== "suspended" && status !== "blocked") {
        res.status(400).json({
          success: false,
          message: "status must be 'active', 'suspended', or 'blocked'",
        });
        return;
      }
      const data = await adminService.updateClientStatus(id, status);
      res.status(200).json({ success: true, message: "Client status updated", data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error updating client status";
      const code = message.includes("not found") ? 404 : message.includes("status must") ? 400 : 500;
      res.status(code).json({ success: false, message });
    }
  }

  async getRiderPerformance(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      if (!id) {
        res.status(400).json({ success: false, message: "Rider id is required" });
        return;
      }
      const raw = typeof req.query.months === "string" ? parseInt(req.query.months, 10) : 12;
      const months = Number.isFinite(raw) ? Math.min(Math.max(raw, 3), 24) : 12;
      const data = await adminService.getRiderPerformance(id, months);
      if (!data) {
        res.status(404).json({ success: false, message: "Rider not found" });
        return;
      }
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching rider performance";
      res.status(500).json({ success: false, message });
    }
  }

  async listComplaints(req: AuthRequest, res: Response): Promise<void> {
    try {
      const reporterType = typeof req.query.reporterType === "string" ? req.query.reporterType.trim() : undefined;
      const status = typeof req.query.status === "string" ? req.query.status.trim() : undefined;
      const rawLimit =
        typeof req.query.limit === "string" ? parseInt(req.query.limit, 10) : undefined;
      const limit = rawLimit !== undefined && Number.isFinite(rawLimit) ? rawLimit : undefined;
      const data = await complaintService.listForAdmin({
        reporterType: reporterType || undefined,
        status: status || undefined,
        limit,
      });
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching complaints";
      res.status(500).json({ success: false, message });
    }
  }

  async getComplaint(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      if (!id) {
        res.status(400).json({ success: false, message: "Complaint id is required" });
        return;
      }
      const data = await complaintService.getByIdForAdmin(id);
      if (!data) {
        res.status(404).json({ success: false, message: "Complaint not found" });
        return;
      }
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching complaint";
      res.status(500).json({ success: false, message });
    }
  }

  async updateComplaintStatus(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const { status } = req.body as { status?: string };
      if (!id) {
        res.status(400).json({ success: false, message: "Complaint id is required" });
        return;
      }
      if (!status) {
        res.status(400).json({ success: false, message: "status is required" });
        return;
      }
      const data = await complaintService.updateStatus(id, status);
      if (!data) {
        res.status(404).json({ success: false, message: "Complaint not found" });
        return;
      }
      res.status(200).json({ success: true, message: "Complaint status updated", data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error updating complaint status";
      const code = message.includes("status must") ? 400 : message.includes("not found") ? 404 : 500;
      res.status(code).json({ success: false, message });
    }
  }

  async listMessages(req: AuthRequest, res: Response): Promise<void> {
    try {
      const rawLimit =
        typeof req.query.limit === "string" ? parseInt(req.query.limit, 10) : undefined;
      const limit = rawLimit !== undefined && Number.isFinite(rawLimit) ? rawLimit : undefined;
      const unreadOnly =
        typeof req.query.unreadOnly === "string" &&
        ["1", "true", "yes"].includes(req.query.unreadOnly.toLowerCase());
      const data = await contactService.listForAdmin({ limit, unreadOnly });
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching messages";
      res.status(500).json({ success: false, message });
    }
  }

  async getMessage(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      if (!id) {
        res.status(400).json({ success: false, message: "Message id is required" });
        return;
      }
      const data = await contactService.getByIdForAdmin(id);
      if (!data) {
        res.status(404).json({ success: false, message: "Message not found" });
        return;
      }
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching message";
      const status = message.toLowerCase().includes("invalid") ? 400 : 500;
      res.status(status).json({ success: false, message });
    }
  }
}
