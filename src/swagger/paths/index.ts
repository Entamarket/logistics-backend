import { authPaths } from "./auth.paths";
import { shipmentPaths } from "./shipments.paths";
import { riderPaths } from "./riders.paths";
import { notificationPaths } from "./notifications.paths";
import { feedbackPaths } from "./feedback.paths";
import { complaintPaths } from "./complaints.paths";
import { contactPaths } from "./contact.paths";
import { adminPaths } from "./admin.paths";
import { paymentPaths } from "./payments.paths";

export const rootPaths = {
  "/": {
    get: {
      tags: ["Health"],
      summary: "Server health check",
      responses: {
        "200": {
          description: "Plain text status",
          content: {
            "text/plain": {
              schema: { type: "string", example: "Server is running on port 4000" },
            },
          },
        },
      },
    },
  },
};

export const openApiPaths = {
  ...rootPaths,
  ...authPaths,
  ...shipmentPaths,
  ...riderPaths,
  ...notificationPaths,
  ...feedbackPaths,
  ...complaintPaths,
  ...contactPaths,
  ...adminPaths,
  ...paymentPaths,
};
