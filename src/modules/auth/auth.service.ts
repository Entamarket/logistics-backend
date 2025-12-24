import bcrypt from "bcrypt";
import jwt, { SignOptions } from "jsonwebtoken";
import { User, IUser } from "../../shared/models/User";
import { EmailVerification } from "../../shared/models/EmailVerification";
import { EmailVerificationPurpose } from "../../shared/lib/enums";
import type { StringValue } from "ms";
import { sendOTPEmail, sendPasswordResetOTPEmail } from "../../config/email";
import { generateOTP } from "../../shared/lib/utils";
import { logger } from "../../shared/lib/logger";

export interface SignUpData {
  firstName: string;
  lastName: string;
  email: string;
  phone: string;
  password: string;
}

export interface LoginData {
  email: string;
  password: string;
}

export interface VerifyEmailData {
  email: string;
  otp: string;
}

export interface ForgotPasswordData {
  email: string;
}

export interface ResetPasswordData {
  email: string;
  otp: string;
  newPassword: string;
}

export interface ResendOTPData {
  email: string;
  purpose: EmailVerificationPurpose;
}

export type UserWithoutPassword = Omit<IUser, "password">;

export interface LoginResponse {
  user: UserWithoutPassword;
  token: string;
}

export class AuthService {
  private generateToken(user: IUser): string {
    const jwtSecret = process.env.JWT_SECRET || "your-secret-key-change-in-production";
    const expiresIn = (process.env.JWT_EXPIRES_IN || "7d") as StringValue;
    const signOptions: SignOptions = {
      expiresIn,
    };
    return jwt.sign(
      {
        id: user._id.toString(),
        email: user.email,
        role: user.role,
      },
      jwtSecret,
      signOptions
    );
  }

  async signUp(data: SignUpData): Promise<UserWithoutPassword> {
    // Check if user already exists
    const existingUser = await User.findOne({ email: data.email });
    if (existingUser) {
      throw new Error("User with this email already exists");
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(data.password, saltRounds);

    // Create new user with role = "client"
    const user = new User({
      firstName: data.firstName,
      lastName: data.lastName,
      email: data.email,
      phone: data.phone,
      password: hashedPassword,
      role: "client",
      isEmailVerified: false,
    });

    await user.save();

    // Generate 6-digit OTP
    const otp = generateOTP();
    
    // Hash OTP with bcrypt
    const saltRoundsOTP = 10;
    const otpHash = await bcrypt.hash(otp, saltRoundsOTP);

    // Create expiration date (1 hour from now)
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    // Create email verification record
    const emailVerification = new EmailVerification({
      userId: user._id,
      otpHash,
      purpose: EmailVerificationPurpose.EMAIL_VERIFICATION,
      expiresAt,
      attempts: 0,
    });

    await emailVerification.save();

    // Send OTP email (don't await to avoid blocking the response)
    sendOTPEmail(data.email, otp, data.firstName).catch((error) => {
      logger.error("Failed to send OTP email", { error, email: data.email });
      // Don't throw error - user is created, they can request OTP resend later
    });

    // Remove password from returned user object
    const userObject = user.toObject();
    const { password: _, ...userWithoutPassword } = userObject;

    return userWithoutPassword as unknown as UserWithoutPassword;
  }

  async login(data: LoginData): Promise<LoginResponse> {
    // Find user by email
    const user = await User.findOne({ email: data.email });
    if (!user) {
      throw new Error("Invalid email or password");
    }

    // Compare password (only if user has a password)
    if (user.password) {
      const isPasswordValid = await bcrypt.compare(data.password, user.password);
      if (!isPasswordValid) {
        throw new Error("Invalid email or password");
      }
    } else {
      throw new Error("Invalid email or password");
    }

    // Check if email is verified
    if (!user.isEmailVerified) {
      // Delete any existing OTP records for this user
      await EmailVerification.deleteMany({ userId: user._id });

      // Generate new 6-digit OTP
      const otp = generateOTP();

      // Hash OTP with bcrypt
      const saltRoundsOTP = 10;
      const otpHash = await bcrypt.hash(otp, saltRoundsOTP);

      // Create expiration date (1 hour from now)
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

      // Create new email verification record
      const emailVerification = new EmailVerification({
        userId: user._id,
        otpHash,
        purpose: EmailVerificationPurpose.EMAIL_VERIFICATION,
        expiresAt,
        attempts: 0,
      });

      await emailVerification.save();

      // Send OTP email (don't await to avoid blocking the response)
      sendOTPEmail(user.email, otp, user.firstName).catch((error) => {
        logger.error("Failed to send OTP email", { error, email: user.email });
      });

      // Throw error to indicate email not verified
      throw new Error("EMAIL_NOT_VERIFIED");
    }

    // Remove password from returned user object
    const userObject = user.toObject();
    const { password: _, ...userWithoutPassword } = userObject;

    // Generate JWT token
    const token = this.generateToken(user);

    return {
      user: userWithoutPassword as unknown as UserWithoutPassword,
      token,
    };
  }

  async verifyEmail(data: VerifyEmailData): Promise<UserWithoutPassword> {
    const MAX_ATTEMPTS = 5; // Maximum number of verification attempts allowed

    // Find user by email
    const user = await User.findOne({ email: data.email });
    if (!user) {
      throw new Error("User not found");
    }

    // Check if email is already verified
    if (user.isEmailVerified) {
      throw new Error("Email is already verified");
    }

    // Find the email verification record for this user
    const emailVerification = await EmailVerification.findOne({
      userId: user._id,
      purpose: EmailVerificationPurpose.EMAIL_VERIFICATION,
    });

    if (!emailVerification) {
      throw new Error("No verification code found. Please request a new OTP.");
    }

    // Check if OTP has expired
    if (emailVerification.expiresAt < new Date()) {
      await EmailVerification.deleteOne({ _id: emailVerification._id });
      throw new Error("Verification code has expired. Please request a new OTP.");
    }

    // Check if maximum attempts exceeded
    if (emailVerification.attempts >= MAX_ATTEMPTS) {
      await EmailVerification.deleteOne({ _id: emailVerification._id });
      throw new Error("Too many verification attempts. Please request a new OTP.");
    }

    // Increment attempts
    emailVerification.attempts += 1;
    await emailVerification.save();

    // Compare provided OTP with hashed OTP
    const isOTPValid = await bcrypt.compare(data.otp, emailVerification.otpHash);
    if (!isOTPValid) {
      // If this was the last attempt, delete the record
      if (emailVerification.attempts >= MAX_ATTEMPTS) {
        await EmailVerification.deleteOne({ _id: emailVerification._id });
        throw new Error("Too many verification attempts. Please request a new OTP.");
      }
      throw new Error("Invalid verification code");
    }

    // Mark email as verified
    user.isEmailVerified = true;
    await user.save();

    // Delete the email verification record
    await EmailVerification.deleteOne({ _id: emailVerification._id });

    // Remove password from returned user object
    const userObject = user.toObject();
    const { password: _, ...userWithoutPassword } = userObject;

    return userWithoutPassword as unknown as UserWithoutPassword;
  }

  async forgotPassword(data: ForgotPasswordData): Promise<void> {
    // Find user by email
    const user = await User.findOne({ email: data.email });
    if (!user) {
      // Don't reveal if user exists or not for security reasons
      // Return success even if user doesn't exist
      return;
    }

    // Delete any existing password reset OTP records for this user
    await EmailVerification.deleteMany({
      userId: user._id,
      purpose: EmailVerificationPurpose.PASSWORD_RESET,
    });

    // Generate 6-digit OTP
    const otp = generateOTP();

    // Hash OTP with bcrypt
    const saltRoundsOTP = 10;
    const otpHash = await bcrypt.hash(otp, saltRoundsOTP);

    // Create expiration date (1 hour from now)
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    // Create password reset verification record
    const emailVerification = new EmailVerification({
      userId: user._id,
      otpHash,
      purpose: EmailVerificationPurpose.PASSWORD_RESET,
      expiresAt,
      attempts: 0,
    });

    await emailVerification.save();

    // Send password reset OTP email (don't await to avoid blocking the response)
    sendPasswordResetOTPEmail(user.email, otp, user.firstName).catch((error) => {
      logger.error("Failed to send password reset OTP email", { error, email: user.email });
    });
  }

  async resetPassword(data: ResetPasswordData): Promise<void> {
    const MAX_ATTEMPTS = 5; // Maximum number of verification attempts allowed

    // Find user by email
    const user = await User.findOne({ email: data.email });
    if (!user) {
      throw new Error("User not found");
    }

    // Find the password reset verification record for this user
    const emailVerification = await EmailVerification.findOne({
      userId: user._id,
      purpose: EmailVerificationPurpose.PASSWORD_RESET,
    });

    if (!emailVerification) {
      throw new Error("No verification code found. Please request a new OTP.");
    }

    // Check if OTP has expired
    if (emailVerification.expiresAt < new Date()) {
      await EmailVerification.deleteOne({ _id: emailVerification._id });
      throw new Error("Verification code has expired. Please request a new OTP.");
    }

    // Check if maximum attempts exceeded
    if (emailVerification.attempts >= MAX_ATTEMPTS) {
      await EmailVerification.deleteOne({ _id: emailVerification._id });
      throw new Error("Too many verification attempts. Please request a new OTP.");
    }

    // Increment attempts
    emailVerification.attempts += 1;
    await emailVerification.save();

    // Compare provided OTP with hashed OTP
    const isOTPValid = await bcrypt.compare(data.otp, emailVerification.otpHash);
    if (!isOTPValid) {
      // If this was the last attempt, delete the record
      if (emailVerification.attempts >= MAX_ATTEMPTS) {
        await EmailVerification.deleteOne({ _id: emailVerification._id });
        throw new Error("Too many verification attempts. Please request a new OTP.");
      }
      throw new Error("Invalid verification code");
    }

    // Validate new password length (matching User model validation)
    if (data.newPassword.length < 8) {
      throw new Error("Password must be at least 8 characters");
    }

    // Hash the new password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(data.newPassword, saltRounds);

    // Update user's password
    user.password = hashedPassword;
    await user.save();

    // Delete the password reset verification record
    await EmailVerification.deleteOne({ _id: emailVerification._id });
  }

  async resendOTP(data: ResendOTPData): Promise<void> {
    // Find user by email
    const user = await User.findOne({ email: data.email });
    if (!user) {
      // Don't reveal if user exists or not for security reasons
      // Return success even if user doesn't exist
      return;
    }

    // Validate purpose-specific requirements
    if (data.purpose === EmailVerificationPurpose.EMAIL_VERIFICATION && user.isEmailVerified) {
      throw new Error("Email is already verified");
    }

    // Delete any existing OTP records for this user with the same purpose
    await EmailVerification.deleteMany({
      userId: user._id,
      purpose: data.purpose,
    });

    // Generate 6-digit OTP
    const otp = generateOTP();

    // Hash OTP with bcrypt
    const saltRoundsOTP = 10;
    const otpHash = await bcrypt.hash(otp, saltRoundsOTP);

    // Create expiration date (1 hour from now)
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    // Create email verification record
    const emailVerification = new EmailVerification({
      userId: user._id,
      otpHash,
      purpose: data.purpose,
      expiresAt,
      attempts: 0,
    });

    await emailVerification.save();

    // Send appropriate OTP email based on purpose
    if (data.purpose === EmailVerificationPurpose.EMAIL_VERIFICATION) {
      sendOTPEmail(user.email, otp, user.firstName).catch((error) => {
        logger.error("Failed to send verification OTP email", { error, email: user.email });
      });
    } else if (data.purpose === EmailVerificationPurpose.PASSWORD_RESET) {
      sendPasswordResetOTPEmail(user.email, otp, user.firstName).catch((error) => {
        logger.error("Failed to send password reset OTP email", { error, email: user.email });
      });
    }
  }

}

