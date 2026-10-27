import { Inject, Injectable, OnApplicationShutdown } from "@nestjs/common";
import { RmqRecordBuilder } from "@nestjs/microservices";
import { firstValueFrom, timeout } from "rxjs";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import {
  RPC_PATTERN,
  RpcErrorCodeSchema,
  type Query,
  type Command,
  type RpcResult,
} from "@311/contracts";
import {
  createRpcClient,
  rpcError,
  UpstreamRpcError,
} from "@311/nest-infrastructure";
import { PUBLIC_CONFIG, PublicConfig } from "../config";
export { UpstreamRpcError } from "@311/nest-infrastructure";
@Injectable()
export class GardenRpcService implements OnApplicationShutdown {
  private client;
  constructor(@Inject(PUBLIC_CONFIG) private readonly config: PublicConfig) {
    this.client = createRpcClient(config);
  }
  async call(
    accessToken: string,
    operation: Query | Command,
    idempotencyKey?: string,
    backoffice = false,
  ): Promise<{ data: any }> {
    const requestId = randomUUID();
    const body = {
      schemaVersion: 1,
      meta: {
        requestId,
        correlationId: requestId,
        deadlineAt: new Date(
          Date.now() + this.config.RPC_TIMEOUT_MS,
        ).toISOString(),
        ...(idempotencyKey ? { idempotencyKey } : {}),
      },
      auth: { accessToken, backoffice },
      operation,
    };
    let raw: unknown;
    try {
      raw = await firstValueFrom(
        this.client
          .send(
            RPC_PATTERN,
            new RmqRecordBuilder(body)
              .setOptions({
                expiration: String(this.config.RPC_TIMEOUT_MS),
                persistent: false,
              })
              .build(),
          )
          .pipe(timeout(this.config.RPC_TIMEOUT_MS)),
      );
    } catch {
      throw rpcError("DEPENDENCY_UNAVAILABLE");
    }
    const parsed = z
      .discriminatedUnion("ok", [
        z.object({
          ok: z.literal(true),
          requestId: z.uuid(),
          data: z.unknown(),
        }),
        z.object({
          ok: z.literal(false),
          requestId: z.uuid(),
          error: z.object({
            code: RpcErrorCodeSchema,
            retryable: z.boolean(),
            messageKey: z.string(),
          }),
        }),
      ])
      .safeParse(raw);
    if (!parsed.success || parsed.data.requestId !== requestId)
      throw rpcError("INVALID_UPSTREAM_RESPONSE");
    if (!parsed.data.ok)
      throw new UpstreamRpcError(requestId, parsed.data.error);
    return { data: parsed.data.data };
  }
  profile(token: string) {
    return this.call(token, { type: "profile" });
  }
  async onApplicationShutdown() {
    await this.client.close();
  }
}
