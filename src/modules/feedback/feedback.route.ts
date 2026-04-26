import { Router } from "express";
import { authMiddleware, AuthRequest } from "../../shared/middlewares/auth.middleware";
import { FeedbackController } from "./feedback.controller";

const router = Router();
const feedbackController = new FeedbackController();

router.use(authMiddleware);

router.get("/mine", (req, res) => feedbackController.listMine(req as AuthRequest, res));
router.post("/", (req, res) => feedbackController.create(req as AuthRequest, res));

export default router;
