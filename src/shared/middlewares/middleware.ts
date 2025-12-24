import express, { Express } from "express";
import cookieParser from "cookie-parser";
import { corsMiddleware } from "../../config/cors";

export const setupMiddleware = (app: Express): void => {
  // CORS middleware (must be before other middleware)
  app.use(corsMiddleware);

  // Body parser middleware
  app.use(express.json());

  // Cookie parser middleware
  app.use(cookieParser());

};