import { Router } from "express";
import { authMiddleware, AuthRequest } from "../../shared/middlewares/auth.middleware";
import { adminMiddleware } from "../../shared/middlewares/admin.middleware";
import { AdminController } from "./admin.controller";

const router = Router();
const adminController = new AdminController();

router.use(authMiddleware);
router.use(adminMiddleware);

router.get("/revenue", (req, res) => adminController.revenueSummary(req as AuthRequest, res));
router.get("/financial-reports", (req, res) => adminController.financialReports(req as AuthRequest, res));
router.get("/financial-reports/:yearMonth", (req, res) =>
  adminController.financialReportMonth(req as AuthRequest, res)
);
router.get("/available-riders", (req, res) => adminController.listAvailableRiders(req as AuthRequest, res));
router.get("/shipments/export", (req, res) => adminController.exportShipments(req as AuthRequest, res));
router.get("/shipments", (req, res) => adminController.listShipments(req as AuthRequest, res));
router.post("/shipments/bulk", (req, res) => adminController.bulkCreateShipments(req as AuthRequest, res));
router.patch("/shipments/:id/assign", (req, res) => adminController.assignShipment(req as AuthRequest, res));
router.get("/shipments/:id", (req, res) => adminController.getShipment(req as AuthRequest, res));

router.get("/riders/:id/performance", (req, res) => adminController.getRiderPerformance(req as AuthRequest, res));

router.get("/complaints", (req, res) => adminController.listComplaints(req as AuthRequest, res));
router.patch("/complaints/:id/status", (req, res) => adminController.updateComplaintStatus(req as AuthRequest, res));
router.get("/complaints/:id", (req, res) => adminController.getComplaint(req as AuthRequest, res));

router.get("/messages", (req, res) => adminController.listMessages(req as AuthRequest, res));
router.get("/messages/:id", (req, res) => adminController.getMessage(req as AuthRequest, res));

router.get("/clients", (req, res) => adminController.listClients(req as AuthRequest, res));
router.get("/clients/:id/activity", (req, res) => adminController.getClientActivity(req as AuthRequest, res));
router.patch("/clients/:id/status", (req, res) => adminController.updateClientStatus(req as AuthRequest, res));
router.get("/clients/:id", (req, res) => adminController.getClient(req as AuthRequest, res));

export default router;
