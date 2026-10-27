import { randomUUID } from "node:crypto";
import { Request, Response, NextFunction } from "express";
import { z } from "zod";

export interface RequestContext {
  requestId: string;
  correlationId: string;
}
export type ContextRequest = Request & { garden: RequestContext };

export function requestContext(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const requestId = randomUUID();
  const parsed = z.uuid().safeParse(req.headers["x-correlation-id"]);
  const correlationId = parsed.success ? parsed.data : requestId;
  (req as ContextRequest).garden = { requestId, correlationId };
  res.setHeader("X-Request-Id", requestId);
  res.setHeader("X-Correlation-Id", correlationId);
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  next();
}
