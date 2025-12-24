import { Router } from "express";
import { AuthController } from "./auth.controller";

const router = Router();
const authController = new AuthController();

// Sign up route
router.post("/signup", (req, res) => authController.signUp(req, res));

// Login route
router.post("/login", (req, res) => authController.login(req, res));

// Verify email route
router.post("/verify-email", (req, res) => authController.verifyEmail(req, res));

// Forgot password route
router.post("/forgot-password", (req, res) => authController.forgotPassword(req, res));

// Reset password route
router.post("/reset-password", (req, res) => authController.resetPassword(req, res));

// Logout route
router.post("/logout", (req, res) => authController.logout(req, res));

// Resend OTP route
router.post("/resend-otp", (req, res) => authController.resendOTP(req, res));

export default router;

