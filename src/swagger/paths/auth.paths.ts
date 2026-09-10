import { cookieSecurity } from "../components";

export const authPaths = {
  "/api/auth/signup": {
    post: {
      tags: ["Auth"],
      summary: "Register a new client account",
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["firstName", "lastName", "email", "password"],
              properties: {
                firstName: { type: "string", example: "Ada" },
                lastName: { type: "string", example: "Okafor" },
                email: { type: "string", format: "email", example: "ada@example.com" },
                phone: {
                  type: "string",
                  example: "+2348012345678",
                  description: "Optional. When provided, must be unique.",
                },
                password: { type: "string", minLength: 8, example: "SecurePass123" },
              },
            },
          },
        },
      },
      responses: {
        "201": {
          description: "User created",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  message: { type: "string", example: "User created successfully" },
                  data: {
                    type: "object",
                    properties: {
                      id: { type: "string" },
                      firstName: { type: "string" },
                      lastName: { type: "string" },
                      email: { type: "string" },
                      role: { type: "string", example: "client" },
                    },
                  },
                },
              },
            },
          },
        },
        "400": { description: "Validation error", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/auth/login": {
    post: {
      tags: ["Auth"],
      summary: "Log in with email or phone + password (sets httpOnly token cookie)",
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["password"],
              properties: {
                identifier: {
                  type: "string",
                  example: "ada@example.com",
                  description: "Email address or phone number",
                },
                email: {
                  type: "string",
                  example: "ada@example.com",
                  description: "Alias for identifier (email or phone). Kept for compatibility.",
                },
                phone: {
                  type: "string",
                  example: "+2348012345678",
                  description: "Alias for identifier when logging in with phone",
                },
                password: { type: "string", example: "SecurePass123" },
              },
            },
          },
        },
      },
      responses: {
        "200": {
          description: "Login successful; Set-Cookie token",
          headers: {
            "Set-Cookie": {
              schema: { type: "string", example: "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...; HttpOnly" },
            },
          },
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  message: { type: "string", example: "Login successful" },
                  data: { $ref: "#/components/schemas/AuthUser" },
                },
              },
            },
          },
        },
        "403": {
          description: "Email not verified or account suspended/blocked",
          content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } },
        },
        "401": { description: "Invalid credentials", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/auth/verify-email": {
    post: {
      tags: ["Auth"],
      summary: "Verify email with OTP",
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["email", "otp"],
              properties: {
                email: { type: "string", example: "ada@example.com" },
                otp: { type: "string", example: "482910" },
              },
            },
          },
        },
      },
      responses: {
        "200": {
          description: "Email verified",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  data: {
                    allOf: [
                      { $ref: "#/components/schemas/AuthUser" },
                      { type: "object", properties: { isEmailVerified: { type: "boolean", example: true } } },
                    ],
                  },
                },
              },
            },
          },
        },
        "400": { description: "Invalid OTP", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/auth/forgot-password": {
    post: {
      tags: ["Auth"],
      summary: "Request password reset OTP",
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["email"],
              properties: { email: { type: "string", example: "ada@example.com" } },
            },
          },
        },
      },
      responses: {
        "200": {
          description: "Always returns success (no user enumeration)",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  message: { type: "string", example: "If an account exists, a reset code has been sent." },
                },
              },
            },
          },
        },
      },
    },
  },
  "/api/auth/reset-password": {
    post: {
      tags: ["Auth"],
      summary: "Reset password with OTP",
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["email", "otp", "newPassword"],
              properties: {
                email: { type: "string", example: "ada@example.com" },
                otp: { type: "string", example: "391827" },
                newPassword: { type: "string", minLength: 8, example: "NewSecurePass456" },
              },
            },
          },
        },
      },
      responses: {
        "200": { description: "Password reset", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiSuccessMessage" } } } },
        "400": { description: "Invalid OTP or password", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/auth/logout": {
    post: {
      tags: ["Auth"],
      summary: "Clear auth cookie",
      responses: {
        "200": {
          description: "Logged out",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  message: { type: "string", example: "Logged out successfully" },
                },
              },
            },
          },
        },
      },
    },
  },
  "/api/auth/resend-otp": {
    post: {
      tags: ["Auth"],
      summary: "Resend OTP",
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["email", "purpose"],
              properties: {
                email: { type: "string", example: "ada@example.com" },
                purpose: {
                  type: "string",
                  enum: ["Email verification", "Password reset"],
                  example: "Email verification",
                },
              },
            },
          },
        },
      },
      responses: {
        "200": { description: "OTP sent", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiSuccessMessage" } } } },
        "400": { description: "Invalid purpose", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/auth/me": {
    get: {
      tags: ["Auth"],
      summary: "Get current user profile",
      security: cookieSecurity,
      responses: {
        "200": {
          description: "Profile",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  data: { $ref: "#/components/schemas/UserProfile" },
                },
              },
            },
          },
        },
        "401": { description: "Not authenticated", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
    patch: {
      tags: ["Auth"],
      summary: "Update current user profile",
      security: cookieSecurity,
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["firstName", "lastName", "phone"],
              properties: {
                firstName: { type: "string", example: "Jane" },
                lastName: { type: "string", example: "Doe" },
                phone: { type: "string", example: "+2348012345678" },
              },
            },
          },
        },
      },
      responses: {
        "200": {
          description: "Updated profile",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  message: { type: "string", example: "Profile updated successfully" },
                  data: { $ref: "#/components/schemas/UserProfile" },
                },
              },
            },
          },
        },
        "400": { description: "Validation error", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/auth/me/email/request": {
    post: {
      tags: ["Auth"],
      summary: "Request email change (sends OTP to new email)",
      description:
        "Requires the current account password. Sends a verification OTP to the new email address. The email is not changed until confirmed.",
      security: cookieSecurity,
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["newEmail", "currentPassword"],
              properties: {
                newEmail: { type: "string", format: "email", example: "new@example.com" },
                currentPassword: { type: "string", example: "CurrentPass123" },
              },
            },
          },
        },
      },
      responses: {
        "200": {
          description: "OTP sent",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  message: { type: "string" },
                  data: {
                    type: "object",
                    properties: { pendingEmail: { type: "string", example: "new@example.com" } },
                  },
                },
              },
            },
          },
        },
        "400": { description: "Validation error", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
        "401": { description: "Auth required or wrong password", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/auth/me/email/confirm": {
    post: {
      tags: ["Auth"],
      summary: "Confirm email change with OTP",
      security: cookieSecurity,
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["otp"],
              properties: {
                otp: { type: "string", example: "123456" },
              },
            },
          },
        },
      },
      responses: {
        "200": {
          description: "Email updated",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  message: { type: "string" },
                  data: { $ref: "#/components/schemas/UserProfile" },
                },
              },
            },
          },
        },
        "400": { description: "Invalid or expired OTP", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
        "401": { description: "Not authenticated", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/auth/me/email/resend": {
    post: {
      tags: ["Auth"],
      summary: "Resend email-change OTP to pending new email",
      security: cookieSecurity,
      responses: {
        "200": {
          description: "OTP resent",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  message: { type: "string" },
                  data: {
                    type: "object",
                    properties: { pendingEmail: { type: "string", example: "new@example.com" } },
                  },
                },
              },
            },
          },
        },
        "400": { description: "No pending email change", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
        "401": { description: "Not authenticated", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/auth/me/password": {
    post: {
      tags: ["Auth"],
      summary: "Change password while authenticated",
      description: "Requires the current password. No OTP. New password must be at least 8 characters and different from the current one.",
      security: cookieSecurity,
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["currentPassword", "newPassword"],
              properties: {
                currentPassword: { type: "string", example: "OldPass123" },
                newPassword: { type: "string", minLength: 8, example: "NewPass123" },
              },
            },
          },
        },
      },
      responses: {
        "200": {
          description: "Password updated",
          content: { "application/json": { schema: { $ref: "#/components/schemas/ApiSuccessMessage" } } },
        },
        "400": { description: "Validation error", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
        "401": { description: "Auth required or wrong current password", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
  "/api/auth/ws-token": {
    get: {
      tags: ["Auth"],
      summary: "Get JWT for WebSocket (?token=)",
      security: cookieSecurity,
      responses: {
        "200": {
          description: "JWT for ws://host/ws?token=",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  data: {
                    type: "object",
                    properties: { token: { type: "string", example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." } },
                  },
                },
              },
            },
          },
        },
        "401": { description: "Not authenticated", content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } } },
      },
    },
  },
};
