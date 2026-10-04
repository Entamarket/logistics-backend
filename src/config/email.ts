import { Resend } from "resend";
import { logger } from "../shared/lib/logger";

function getResendClient(): Resend | null {
  const apiKey = process.env.RESEND_API_KEY?.trim();
  if (!apiKey) return null;
  return new Resend(apiKey);
}

/**
 * Send email via Resend.
 * @param to - Recipient email address
 * @param subject - Email subject
 * @param html - Email HTML content
 * @param text - Email plain text content (optional)
 */
export const sendEmail = async (
  to: string,
  subject: string,
  html: string,
  text?: string,
  options?: { replyTo?: string }
): Promise<void> => {
  const from = process.env.MAIL_FROM?.trim();
  const resend = getResendClient();
  if (!resend || !from) {
    logger.warn("Mail not configured (RESEND_API_KEY or MAIL_FROM missing), skipping send", {
      to,
      subject,
      hasApiKey: Boolean(process.env.RESEND_API_KEY?.trim()),
      hasFrom: Boolean(from),
    });
    return;
  }

  try {
    const { data, error } = await resend.emails.send({
      from,
      to,
      subject,
      html,
      ...(text ? { text } : {}),
      ...(options?.replyTo ? { replyTo: options.replyTo } : {}),
    });

    if (error) {
      logger.error("Error sending email via Resend", { error, to, subject });
      throw new Error("Failed to send email");
    }

    logger.info("Email sent successfully", { messageId: data?.id, to });
  } catch (error) {
    if (error instanceof Error && error.message === "Failed to send email") throw error;
    logger.error("Error sending email", { error, to });
    throw new Error("Failed to send email");
  }
};

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Notify MAIL_USER about a landing-page contact form submission.
 * Returns "sent" | "skipped" | "failed" so callers can persist delivery status.
 */
export const sendContactMessageNotificationEmail = async (params: {
  name: string;
  email: string;
  phone: string;
  subject: string;
  message: string;
}): Promise<"sent" | "skipped" | "failed"> => {
  const to = process.env.MAIL_USER?.trim();
  if (!process.env.RESEND_API_KEY?.trim() || !to) {
    logger.warn("Mail not configured; skipping contact message notification", {
      hasApiKey: Boolean(process.env.RESEND_API_KEY?.trim()),
      hasUser: Boolean(to),
    });
    return "skipped";
  }

  const displaySubject = params.subject.trim() || "Entamarket Logistics inquiry";
  const mailSubject = `[Contact] ${displaySubject}`;
  const safeName = escapeHtml(params.name);
  const safeEmail = escapeHtml(params.email);
  const safePhone = escapeHtml(params.phone);
  const safeSubject = escapeHtml(displaySubject);
  const safeMessage = escapeHtml(params.message).replace(/\n/g, "<br>");

  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Contact message</title>
    </head>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 640px; margin: 0 auto; padding: 20px;">
      <div style="background-color: #f4f4f4; padding: 20px; border-radius: 5px;">
        <h2 style="color: #81007f; text-align: center; margin-top: 0;">New contact form message</h2>
        <div style="background-color: #fff; padding: 20px; border-radius: 5px; margin: 20px 0;">
          <p style="margin: 0 0 8px 0;"><strong>Name:</strong> ${safeName}</p>
          <p style="margin: 0 0 8px 0;"><strong>Email:</strong> ${safeEmail}</p>
          <p style="margin: 0 0 8px 0;"><strong>Phone:</strong> ${safePhone}</p>
          <p style="margin: 0 0 16px 0;"><strong>Subject:</strong> ${safeSubject}</p>
          <hr style="border: none; border-top: 1px solid #eee; margin: 16px 0;">
          <p style="margin: 0; white-space: pre-wrap;">${safeMessage}</p>
        </div>
        <p style="font-size: 12px; color: #666; text-align: center;">
          Reply directly to this email to respond to ${safeEmail}.
        </p>
      </div>
    </body>
    </html>
  `;

  const text = [
    "New contact form message",
    "",
    `Name: ${params.name}`,
    `Email: ${params.email}`,
    `Phone: ${params.phone}`,
    `Subject: ${displaySubject}`,
    "",
    params.message,
  ].join("\n");

  try {
    await sendEmail(to, mailSubject, html, text, { replyTo: params.email });
    return "sent";
  } catch (error) {
    logger.error("Failed to send contact message notification email", {
      error: error instanceof Error ? error.message : String(error),
      to,
    });
    return "failed";
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

/**
 * Send rider account credentials (email + password) when admin creates a rider
 * @param email - Rider's email address
 * @param firstName - Rider's first name for personalization
 * @param plainPassword - The password set by admin (sent so rider can log in)
 */
export const sendRiderCredentialsEmail = async (
  email: string,
  firstName: string,
  plainPassword: string
): Promise<void> => {
  const subject = "Your rider account – Entamarket Logistics";
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Rider Account</title>
    </head>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
      <div style="background-color: #f4f4f4; padding: 20px; border-radius: 5px;">
        <h2 style="color: #333; text-align: center;">Your rider account has been created</h2>
        <p>Hello ${firstName},</p>
        <p>An administrator has created a rider account for you on Entamarket Logistics. You can log in using the details below.</p>
        <div style="background-color: #fff; padding: 20px; border-radius: 5px; margin: 20px 0;">
          <p style="margin: 0 0 8px 0;"><strong>Email:</strong> ${email}</p>
          <p style="margin: 0;"><strong>Password:</strong> ${plainPassword}</p>
        </div>
        <p>Please keep these details secure. You can use them to log in to the rider portal.</p>
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

    An administrator has created a rider account for you on Entamarket Logistics. You can log in using the details below.

    Email: ${email}
    Password: ${plainPassword}

    Please keep these details secure. You can use them to log in to the rider portal.

    © ${new Date().getFullYear()} Entamarket Logistics. All rights reserved.
  `;

  await sendEmail(email, subject, html, text);
};

function adminLoginUrl(): string {
  const origins = process.env.CORS_ORIGINS?.split(",") ?? [];
  const origin = origins.map((s) => s.trim()).find(Boolean);
  if (origin) return `${origin.replace(/\/$/, "")}/auth/login`;
  return "/auth/login";
}

/**
 * Send admin account credentials when an existing admin creates another admin.
 */
export const sendAdminCredentialsEmail = async (
  email: string,
  firstName: string,
  plainPassword: string
): Promise<void> => {
  const loginUrl = adminLoginUrl();
  const subject = "Your admin account – Entamarket Logistics";
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Admin Account</title>
    </head>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
      <div style="background-color: #f4f4f4; padding: 20px; border-radius: 5px;">
        <h2 style="color: #333; text-align: center;">Your admin account has been created</h2>
        <p>Hello ${firstName},</p>
        <p>An administrator has created an admin account for you on Entamarket Logistics. You can log in using the details below.</p>
        <div style="background-color: #fff; padding: 20px; border-radius: 5px; margin: 20px 0;">
          <p style="margin: 0 0 8px 0;"><strong>Email:</strong> ${email}</p>
          <p style="margin: 0 0 8px 0;"><strong>Password:</strong> ${plainPassword}</p>
          <p style="margin: 0;"><strong>Sign in:</strong> <a href="${loginUrl}">${loginUrl}</a></p>
        </div>
        <p>Please keep these details secure. After signing in you will have access to the admin dashboard.</p>
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

    An administrator has created an admin account for you on Entamarket Logistics. You can log in using the details below.

    Email: ${email}
    Password: ${plainPassword}
    Sign in: ${loginUrl}

    Please keep these details secure. After signing in you will have access to the admin dashboard.

    © ${new Date().getFullYear()} Entamarket Logistics. All rights reserved.
  `;

  await sendEmail(email, subject, html, text);
};

/**
 * Send OTP to confirm a requested email address change
 */
export const sendEmailChangeOTPEmail = async (
  email: string,
  otp: string,
  firstName: string
): Promise<void> => {
  const subject = "Confirm Your New Email - Entamarket Logistics";
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Confirm Email Change</title>
    </head>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
      <div style="background-color: #f4f4f4; padding: 20px; border-radius: 5px;">
        <h2 style="color: #333; text-align: center;">Confirm your new email</h2>
        <p>Hello ${firstName},</p>
        <p>We received a request to change the email address on your Entamarket Logistics account to <strong>${email}</strong>.</p>
        <p>Please use the following verification code to confirm this change:</p>
        <div style="background-color: #fff; padding: 20px; text-align: center; border-radius: 5px; margin: 20px 0;">
          <h1 style="color: #81007f; font-size: 32px; letter-spacing: 5px; margin: 0;">${otp}</h1>
        </div>
        <p>This code will expire in 10 minutes.</p>
        <p>If you didn't request this change, you can ignore this email. Your account email will remain unchanged.</p>
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

    We received a request to change the email address on your Entamarket Logistics account to ${email}.

    Please use the following verification code to confirm this change:

    ${otp}

    This code will expire in 10 minutes.

    If you didn't request this change, you can ignore this email. Your account email will remain unchanged.

    © ${new Date().getFullYear()} Entamarket Logistics. All rights reserved.
  `;

  await sendEmail(email, subject, html, text);
};
