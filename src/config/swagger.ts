import { Express } from "express";
import swaggerUi from "swagger-ui-express";
import { openApiSpec } from "../swagger/spec";
import { logger } from "../shared/lib/logger";

export const setupSwagger = (app: Express): void => {
  app.get("/api-docs.json", (_req, res) => {
    res.json(openApiSpec);
  });

  app.use(
    "/api-docs",
    swaggerUi.serve,
    swaggerUi.setup(openApiSpec, {
      customSiteTitle: "Entamarket Logistics API",
      swaggerOptions: {
        persistAuthorization: true,
        tryItOutEnabled: true,
      },
    })
  );

  logger.info("Swagger UI available at /api-docs");
};
