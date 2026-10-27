import {
  BaseConfigSchema,
  AuthConfigFields,
  validateAuthConfig,
  readConfig,
} from "@311/nest-infrastructure";
import { z } from "zod";
export const PUBLIC_CONFIG = Symbol("PUBLIC_CONFIG");
const schema = BaseConfigSchema.extend({
  ...AuthConfigFields,
  HTTP_PORT: BaseConfigSchema.shape.HTTP_PORT.default(3312),
  REDIS_KEY_PREFIX: z.string().default("311:pub:"),
  PUBLIC_ORIGIN: z.url().default("http://127.0.0.1:5178"),
  BACKOFFICE_ORIGIN: z.url().optional(),
  VAPID_PUBLIC_KEY: z.string().optional(),
  SESSION_ENCRYPTION_KEY_BASE64: z.string().optional(),
}).superRefine((c, ctx) => {
  validateAuthConfig(c, ctx);
  if (new URL(c.PUBLIC_ORIGIN).origin !== c.PUBLIC_ORIGIN)
    ctx.addIssue({
      code: "custom",
      path: ["PUBLIC_ORIGIN"],
      message: "Exact origin required",
    });
  if (
    c.AUTH_ENABLED &&
    (!c.SESSION_ENCRYPTION_KEY_BASE64 ||
      Buffer.from(c.SESSION_ENCRYPTION_KEY_BASE64, "base64").length !== 32)
  )
    ctx.addIssue({
      code: "custom",
      path: ["SESSION_ENCRYPTION_KEY_BASE64"],
      message: "32-byte key required",
    });
  if (
    c.NODE_ENV === "production" &&
    (!c.AUTH_ENABLED || !c.PUBLIC_ORIGIN.startsWith("https://"))
  )
    ctx.addIssue({
      code: "custom",
      path: ["AUTH_ENABLED"],
      message: "Production requires auth and TLS",
    });
});
export type PublicConfig = z.infer<typeof schema>;
export const config = readConfig(schema, process.env);
