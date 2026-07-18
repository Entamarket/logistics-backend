import { Router } from "express";
import { ContactController } from "./contact.controller";

const router = Router();
const contactController = new ContactController();

/** Public — landing page contact form (no auth). */
router.post("/messages", (req, res) => contactController.create(req, res));

export default router;
