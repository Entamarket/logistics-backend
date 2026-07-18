export const contactPaths = {
  "/api/contact/messages": {
    post: {
      tags: ["Contact"],
      summary: "Submit landing-page contact message (public)",
      description:
        "Persists the message for the admin Messages inbox and emails the same content to `MAIL_USER`. No authentication required.",
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["name", "email", "phone", "message"],
              properties: {
                name: { type: "string", example: "Ada Okafor", maxLength: 120 },
                email: { type: "string", format: "email", example: "ada@example.com" },
                phone: {
                  type: "string",
                  example: "+2348012345678",
                  minLength: 6,
                  maxLength: 30,
                },
                subject: {
                  type: "string",
                  example: "Partnership inquiry",
                  maxLength: 200,
                  description: "Optional",
                },
                message: {
                  type: "string",
                  example: "I would like to discuss a logistics partnership.",
                  minLength: 10,
                  maxLength: 5000,
                },
              },
            },
          },
        },
      },
      responses: {
        "201": {
          description: "Message saved (email may be sent, skipped, or failed independently)",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  success: { type: "boolean", example: true },
                  message: { type: "string", example: "Message sent successfully" },
                  data: { $ref: "#/components/schemas/ContactMessage" },
                },
              },
            },
          },
        },
        "400": {
          description: "Validation error",
          content: { "application/json": { schema: { $ref: "#/components/schemas/ApiError" } } },
        },
      },
    },
  },
};
