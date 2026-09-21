import { CookieOptions, Request, Response } from "express";
import { AuthService } from "./auth.service";
import { EmailVerificationPurpose } from "../../shared/lib/enums";
import { AuthRequest } from "../../shared/middlewares/auth.middleware";

const authService = new AuthService();

export class AuthController {
  private setAuthCookie(res: Response, token: string): void {
    const cookieOptions: CookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    };
    res.cookie("token", token, cookieOptions);
  }

  private clearAuthCookie(res: Response): void {
    const cookieOptions: CookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
    };
    res.clearCookie("token", cookieOptions);
  }
  async signUp(req: Request, res: Response): Promise<void> {
    try {
      const { firstName, lastName, email, phone, password } = req.body;

      // Validate required fields (phone is optional)
      if (!firstName || !lastName || !email || !password) {
        res.status(400).json({
          success: false,
          message: "firstName, lastName, email, and password are required",
        });
        return;
      }

      // Create user
      const user = await authService.signUp({
        firstName,
        lastName,
        email,
        phone,
        password,
      });

      res.status(201).json({
        success: true,
        message: "User created successfully",
        data: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          role: user.role,
        },
      });
    } catch (error: any) {
      res.status(400).json({
        success: false,
        message: error.message || "Error creating user",
      });
    }
  }

  async login(req: Request, res: Response): Promise<void> {
    try {
      const { email, phone, identifier, password } = req.body as {
        email?: string;
        phone?: string;
        identifier?: string;
        password?: string;
      };

      const loginId = (identifier ?? email ?? phone ?? "").trim();

      // Validate required fields
      if (!loginId || !password) {
        res.status(400).json({
          success: false,
          message: "Email or phone number, and password are required",
        });
        return;
      }

      // Authenticate user
      const { user, token } = await authService.login({
        identifier: loginId,
        password,
      });

      // Set JWT token in cookie
      this.setAuthCookie(res, token);

      res.status(200).json({
        success: true,
        message: "Login successful",
        data: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          role: user.role,
        },
      });
    } catch (error: any) {
      // Handle unverified email case
      if (error.message === "EMAIL_NOT_VERIFIED") {
        const unverifiedEmail =
          typeof error === "object" && error && "email" in error
            ? String((error as { email?: string }).email ?? "")
            : "";
        res.status(403).json({
          success: false,
          code: "EMAIL_NOT_VERIFIED",
          message: "Email not verified. An OTP has been sent to your email. Please verify your email to continue.",
          ...(unverifiedEmail ? { data: { email: unverifiedEmail } } : {}),
        });
        return;
      }

      // Handle other errors
      res.status(401).json({
        success: false,
        message: error.message || "Invalid email/phone or password",
      });
    }
  }

  async verifyEmail(req: Request, res: Response): Promise<void> {
    try {
      const { email, otp } = req.body;

      // Validate required fields
      if (!email || !otp) {
        res.status(400).json({
          success: false,
          message: "Email and OTP are required",
        });
        return;
      }

      // Verify email
      const user = await authService.verifyEmail({
        email,
        otp,
      });

      res.status(200).json({
        success: true,
        message: "Email verified successfully",
        data: {
          id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          role: user.role,
          isEmailVerified: user.isEmailVerified,
        },
      });
    } catch (error: any) {
      // Determine appropriate status code based on error
      let statusCode = 400;
      if (error.message === "User not found") {
        statusCode = 404;
      } else if (error.message === "Email is already verified") {
        statusCode = 409;
      } else if (
        error.message === "No verification code found. Please request a new OTP." ||
        error.message === "Verification code has expired. Please request a new OTP." ||
        error.message === "Too many verification attempts. Please request a new OTP."
      ) {
        statusCode = 410; // Gone
      }

      res.status(statusCode).json({
        success: false,
        message: error.message || "Error verifying email",
      });
    }
  }

  async forgotPassword(req: Request, res: Response): Promise<void> {
    try {
      const { email } = req.body;

      // Validate required fields
      if (!email) {
        res.status(400).json({
          success: false,
          message: "Email is required",
        });
        return;
      }

      // Request password reset
      await authService.forgotPassword({ email });

      // Always return success message for security (don't reveal if user exists)
      res.status(200).json({
        success: true,
        message: "If an account with that email exists, a password reset OTP has been sent to your email.",
      });
    } catch (error: any) {
      res.status(500).json({
        success: false,
        message: error.message || "Error processing password reset request",
      });
    }
  }

  async resetPassword(req: Request, res: Response): Promise<void> {
    try {
      const { email, otp, newPassword } = req.body;

      // Validate required fields
      if (!email || !otp || !newPassword) {
        res.status(400).json({
          success: false,
          message: "Email, OTP, and new password are required",
        });
        return;
      }

      // Validate password length
      if (newPassword.length < 8) {
        res.status(400).json({
          success: false,
          message: "Password must be at least 8 characters",
        });
        return;
      }

      // Reset password
      await authService.resetPassword({
        email,
        otp,
        newPassword,
      });

      res.status(200).json({
        success: true,
        message: "Password reset successfully. You can now login with your new password.",
      });
    } catch (error: any) {
      // Determine appropriate status code based on error
      let statusCode = 400;
      if (error.message === "User not found") {
        statusCode = 404;
      } else if (
        error.message === "No verification code found. Please request a new OTP." ||
        error.message === "Verification code has expired. Please request a new OTP." ||
        error.message === "Too many verification attempts. Please request a new OTP."
      ) {
        statusCode = 410; // Gone
      }

      res.status(statusCode).json({
        success: false,
        message: error.message || "Error resetting password",
      });
    }
  }

  async logout(_req: Request, res: Response): Promise<void> {
    try {
      // Clear the authentication cookie
      this.clearAuthCookie(res);

      res.status(200).json({
        success: true,
        message: "Logged out successfully",
      });
    } catch (error: any) {
      res.status(500).json({
        success: false,
        message: error.message || "Error during logout",
      });
    }
  }

  async resendOTP(req: Request, res: Response): Promise<void> {
    try {
      const { email, purpose } = req.body;

      // Validate required fields
      if (!email || !purpose) {
        res.status(400).json({
          success: false,
          message: "Email and purpose are required",
        });
        return;
      }

      // Validate purpose
      if (
        purpose !== EmailVerificationPurpose.EMAIL_VERIFICATION &&
        purpose !== EmailVerificationPurpose.PASSWORD_RESET
      ) {
        res.status(400).json({
          success: false,
          message: `Purpose must be either '${EmailVerificationPurpose.EMAIL_VERIFICATION}' or '${EmailVerificationPurpose.PASSWORD_RESET}'`,
        });
        return;
      }

      // Resend OTP
      await authService.resendOTP({ email, purpose });

      // Always return success message for security (don't reveal if user exists)
      const purposeMessage =
        purpose === EmailVerificationPurpose.EMAIL_VERIFICATION
          ? "verification"
          : "password reset";
      
      res.status(200).json({
        success: true,
        message: `If an account with that email exists, a ${purposeMessage} OTP has been sent to your email.`,
      });
    } catch (error: any) {
      // Handle specific errors
      if (error.message === "Email is already verified") {
        res.status(409).json({
          success: false,
          message: error.message,
        });
        return;
      }

      res.status(500).json({
        success: false,
        message: error.message || "Error resending OTP",
      });
    }
  }

  /**
   * Returns the JWT from the httpOnly cookie so the client can open a WebSocket with ?token=
   */
  getWsToken(req: Request, res: Response): void {
    const token = req.cookies?.token as string | undefined;
    if (!token) {
      res.status(401).json({ success: false, message: "Authentication required" });
      return;
    }
    res.status(200).json({
      success: true,
      data: { token },
    });
  }

  async getMe(req: AuthRequest, res: Response): Promise<void> {
    try {
      const userId = req.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: "Authentication required" });
        return;
      }
      const data = await authService.getProfile(userId);
      res.status(200).json({ success: true, data });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error fetching profile";
      res.status(message === "User not found" ? 404 : 500).json({ success: false, message });
    }
  }

  async updateMe(req: AuthRequest, res: Response): Promise<void> {
    try {
      const userId = req.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: "Authentication required" });
        return;
      }
      const { firstName, lastName, phone } = req.body as {
        firstName?: string;
        lastName?: string;
        phone?: string;
      };
      if (!firstName || !lastName || !phone) {
        res.status(400).json({
          success: false,
          message: "firstName, lastName, and phone are required",
        });
        return;
      }
      const data = await authService.updateProfile(userId, { firstName, lastName, phone });
      res.status(200).json({
        success: true,
        message: "Profile updated successfully",
        data,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error updating profile";
      res.status(400).json({ success: false, message });
    }
  }

  async requestEmailChange(req: AuthRequest, res: Response): Promise<void> {
    try {
      const userId = req.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: "Authentication required" });
        return;
      }
      const { newEmail, currentPassword } = req.body as {
        newEmail?: string;
        currentPassword?: string;
      };
      if (!newEmail || !currentPassword) {
        res.status(400).json({
          success: false,
          message: "newEmail and currentPassword are required",
        });
        return;
      }
      const data = await authService.requestEmailChange(userId, { newEmail, currentPassword });
      res.status(200).json({
        success: true,
        message: "A verification code has been sent to your new email address.",
        data,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error requesting email change";
      const status =
        message === "User not found"
          ? 404
          : message === "Current password is incorrect"
            ? 401
            : 400;
      res.status(status).json({ success: false, message });
    }
  }

  async confirmEmailChange(req: AuthRequest, res: Response): Promise<void> {
    try {
      const userId = req.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: "Authentication required" });
        return;
      }
      const { otp } = req.body as { otp?: string };
      if (!otp) {
        res.status(400).json({ success: false, message: "otp is required" });
        return;
      }
      const data = await authService.confirmEmailChange(userId, otp);
      res.status(200).json({
        success: true,
        message: "Email updated successfully",
        data,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error confirming email change";
      res.status(message === "User not found" ? 404 : 400).json({ success: false, message });
    }
  }

  async resendEmailChangeOTP(req: AuthRequest, res: Response): Promise<void> {
    try {
      const userId = req.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: "Authentication required" });
        return;
      }
      const data = await authService.resendEmailChangeOTP(userId);
      res.status(200).json({
        success: true,
        message: "A new verification code has been sent to your new email address.",
        data,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error resending verification code";
      res.status(message === "User not found" ? 404 : 400).json({ success: false, message });
    }
  }

  async changePassword(req: AuthRequest, res: Response): Promise<void> {
    try {
      const userId = req.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: "Authentication required" });
        return;
      }
      const { currentPassword, newPassword } = req.body as {
        currentPassword?: string;
        newPassword?: string;
      };
      if (!currentPassword || !newPassword) {
        res.status(400).json({
          success: false,
          message: "currentPassword and newPassword are required",
        });
        return;
      }
      await authService.changePassword(userId, { currentPassword, newPassword });
      res.status(200).json({
        success: true,
        message: "Password updated successfully",
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error changing password";
      const status =
        message === "User not found"
          ? 404
          : message === "Current password is incorrect"
            ? 401
            : 400;
      res.status(status).json({ success: false, message });
    }
  }

  async deleteAccount(req: AuthRequest, res: Response): Promise<void> {
    try {
      const userId = req.userId;
      if (!userId) {
        res.status(401).json({ success: false, message: "Authentication required" });
        return;
      }
      const { password } = req.body as { password?: string };
      if (!password) {
        res.status(400).json({ success: false, message: "password is required" });
        return;
      }
      await authService.deleteAccount(userId, password);
      this.clearAuthCookie(res);
      res.status(200).json({
        success: true,
        message: "Your account has been permanently deleted",
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Error deleting account";
      const status =
        message === "User not found"
          ? 404
          : message === "Current password is incorrect"
            ? 401
            : 400;
      res.status(status).json({ success: false, message });
    }
  }
}

