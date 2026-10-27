import "reflect-metadata";
import { Module, Controller, Get } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import { json } from "express";
import { GravumRpcClient, RedisConnection } from "@311/nest-infrastructure";
import { config, PUBLIC_CONFIG } from "./config";
import { AuthController } from "./auth/auth.controller";
import { AuthService } from "./auth/auth.service";
import { SessionStore } from "./auth/session-store";
import { BrowserRequestSecurity } from "./auth/browser-request-security";
import { GardenRpcService } from "./rpc/garden-rpc.service";
import { requestContext } from "./http/request-context";
import { HttpErrorFilter } from "./http/error.filter";
import { ApiController } from "./api.controller";
@Controller()
class HealthController {
  @Get("health") health() {
    return {
      service: "311-pub-server",
      alive: true,
      authConfigured: config.AUTH_ENABLED,
    };
  }
}
@Module({
  controllers: [AuthController, ApiController, HealthController],
  providers: [
    { provide: PUBLIC_CONFIG, useValue: config },
    {
      provide: GravumRpcClient,
      useFactory: () => new GravumRpcClient(config, "311-pub-server"),
    },
    {
      provide: RedisConnection,
      useFactory: () =>
        new RedisConnection(config.REDIS_URL, config.REDIS_KEY_PREFIX),
    },
    AuthService,
    SessionStore,
    BrowserRequestSecurity,
    GardenRpcService,
  ],
})
class AppModule {}
async function main() {
  const app = await NestFactory.create(AppModule, { bodyParser: false });
  app.use(json({ limit: "15mb" }));
  app.use(requestContext);
  app.setGlobalPrefix("api");
  app.useGlobalFilters(new HttpErrorFilter());
  app.enableCors({
    origin: [
      config.PUBLIC_ORIGIN,
      ...(config.BACKOFFICE_ORIGIN ? [config.BACKOFFICE_ORIGIN] : []),
    ],
    credentials: true,
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-311-Request",
      "X-311-CSRF",
      "Idempotency-Key",
    ],
  });
  app.enableShutdownHooks();
  await app.listen(config.HTTP_PORT, config.HTTP_HOST);
}
void main();
