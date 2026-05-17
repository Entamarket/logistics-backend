import { Router } from "express";
import { authMiddleware, AuthRequest } from "../../shared/middlewares/auth.middleware";
import { ComplaintController } from "./complaint.controller";

const router = Router();
const complaintController = new ComplaintController();

router.use(authMiddleware);

router.post("/", (req, res) => complaintController.create(req as AuthRequest, res));
router.get("/mine", (req, res) => complaintController.listMine(req as AuthRequest, res));

export default router;
