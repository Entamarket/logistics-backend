import { Request, Response } from "express";
import { ContactService } from "./contact.service";

const contactService = new ContactService();

export class ContactController {
  async create(req: Request, res: Response): Promise<void> {
    try {
      const { name, email, phone, subject, message } = req.body as {
        name?: string;
        email?: string;
        phone?: string;
        subject?: string;
        message?: string;
      };
      if (!name || !email || !phone || !message) {
        res.status(400).json({
          success: false,
          message: "name, email, phone, and message are required",
        });
        return;
      }
      const data = await contactService.create({
        name,
        email,
        phone,
        subject,
        message,
      });
      res.status(201).json({
        success: true,
        message: "Message sent successfully",
        data,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error sending message";
      res.status(400).json({ success: false, message });
    }
  }
}
