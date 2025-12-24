import nodemailer from "nodemailer";
import { logger } from "../shared/lib/logger";

/**
 * Create and configure nodemailer transporter
 */
export const createTransporter = () => {
  const transporter = nodemailer.createTransport({
    host: process.env.MAIL_HOST,
    port: parseInt(process.env.MAIL_PORT || "587"),
    secure: false, // true for 465, false for other ports
    auth: {
      user: process.env.MAIL_USER,
      pass: process.env.MAIL_PASS,
    },
  });

  return transporter;
};

/**
 * Send email using nodemailer
 * @param to - Recipient email address
 * @param subject - Email subject
 * @param html - Email HTML content
 * @param text - Email plain text content (optional)
 */
export const sendEmail = async (
  to: string,
  subject: string,
  html: string,
  text?: string
): Promise<void> => {
  try {
    const transporter = createTransporter();

    const mailOptions = {
      from: process.env.MAIL_FROM || process.env.MAIL_USER,
      to,
      subject,
      text,
      html,
    };

    const info = await transporter.sendMail(mailOptions);
    logger.info("Email sent successfully", { messageId: info.messageId, to });
  } catch (error) {
    logger.error("Error sending email", { error, to });
    throw new Error("Failed to send email");
  }
};

/**
 * Send OTP verification email
 * @param email - Recipient email address
 * @param otp - 6-digit OTP code
 * @param firstName - User's first name for personalization
 */
export const sendOTPEmail = async (
  email: string,
  otp: string,
  firstName: string
): Promise<void> => {
  const subject = "Verify Your Email - Entamarket Logistics";
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Email Verification</title>
    </head>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
      <div style="background-color: #f4f4f4; padding: 20px; border-radius: 5px;">
        <h2 style="color: #333; text-align: center;">Email Verification</h2>
        <p>Hello ${firstName},</p>
        <p>Thank you for signing up with Entamarket Logistics!</p>
        <p>Please use the following verification code to verify your email address:</p>
        <div style="background-color: #fff; padding: 20px; text-align: center; border-radius: 5px; margin: 20px 0;">
          <h1 style="color: #007bff; font-size: 32px; letter-spacing: 5px; margin: 0;">${otp}</h1>
        </div>
        <p>This code will expire in 10 minutes.</p>
        <p>If you didn't create an account with us, please ignore this email.</p>
        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
        <p style="font-size: 12px; color: #666; text-align: center;">
          © ${new Date().getFullYear()} Entamarket Logistics. All rights reserved.
        </p>
      </div>
    </body>
    </html>
  `;

  const text = `
    Hello ${firstName},
    
    Thank you for signing up with Entamarket Logistics!
    
    Please use the following verification code to verify your email address:
    
    ${otp}
    
    This code will expire in 10 minutes.
    
    If you didn't create an account with us, please ignore this email.
    
    © ${new Date().getFullYear()} Entamarket Logistics. All rights reserved.
  `;

  await sendEmail(email, subject, html, text);
};

/**
 * Send password reset OTP email
 * @param email - Recipient email address
 * @param otp - 6-digit OTP code
 * @param firstName - User's first name for personalization
 */
export const sendPasswordResetOTPEmail = async (
  email: string,
  otp: string,
  firstName: string
): Promise<void> => {
  const subject = "Password Reset - Entamarket Logistics";
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Password Reset</title>
    </head>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
      <div style="background-color: #f4f4f4; padding: 20px; border-radius: 5px;">
        <h2 style="color: #333; text-align: center;">Password Reset</h2>
        <p>Hello ${firstName},</p>
        <p>We received a request to reset your password for your Entamarket Logistics account.</p>
        <p>Please use the following verification code to reset your password:</p>
        <div style="background-color: #fff; padding: 20px; text-align: center; border-radius: 5px; margin: 20px 0;">
          <h1 style="color: #dc3545; font-size: 32px; letter-spacing: 5px; margin: 0;">${otp}</h1>
        </div>
        <p>This code will expire in 1 hour.</p>
        <p>If you didn't request a password reset, please ignore this email. Your password will remain unchanged.</p>
        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
        <p style="font-size: 12px; color: #666; text-align: center;">
          © ${new Date().getFullYear()} Entamarket Logistics. All rights reserved.
        </p>
      </div>
    </body>
    </html>
  `;

  const text = `
    Hello ${firstName},
    
    We received a request to reset your password for your Entamarket Logistics account.
    
    Please use the following verification code to reset your password:
    
    ${otp}
    
    This code will expire in 1 hour.
    
    If you didn't request a password reset, please ignore this email. Your password will remain unchanged.
    
    © ${new Date().getFullYear()} Entamarket Logistics. All rights reserved.
  `;

  await sendEmail(email, subject, html, text);
};

