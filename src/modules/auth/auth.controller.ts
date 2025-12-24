import { Request, Response } from "express";
import { AuthService } from "./auth.service";
import { EmailVerificationPurpose } from "../../shared/lib/enums";

const authService = new AuthService();

export class AuthController {
  private setAuthCookie(res: Response, token: string): void {
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict" as const,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    };
    res.cookie("token", token, cookieOptions);
  }

  private clearAuthCookie(res: Response): void {
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict" as const,
    };
    res.clearCookie("token", cookieOptions);
  }
  async signUp(req: Request, res: Response): Promise<void> {
    try {
      const { firstName, lastName, email, phone, password } = req.body;

      // Validate required fields
      if (!firstName || !lastName || !email || !phone || !password) {
        res.status(400).json({
          success: false,
          message: "All fields (firstName, lastName, email, phone, password) are required",
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
      const { email, password } = req.body;

      // Validate required fields
      if (!email || !password) {
        res.status(400).json({
          success: false,
          message: "Email and password are required",
        });
        return;
      }

      // Authenticate user
      const { user, token } = await authService.login({
        email,
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
        res.status(403).json({
          success: false,
          message: "Email not verified. An OTP has been sent to your email. Please verify your email to continue.",
        });
        return;
      }

      // Handle other errors
      res.status(401).json({
        success: false,
        message: error.message || "Invalid email or password",
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

}

