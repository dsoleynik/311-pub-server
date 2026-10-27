import { Inject, Injectable } from "@nestjs/common";
import { randomBytes } from "node:crypto";
import { type Tokens, type LoginInputSchema } from "@311/gravum-contracts";
import { z } from "zod";
import {
  GravumRpcClient,
  ModuleJwtVerifier,
  rpcError,
} from "@311/nest-infrastructure";
import { PUBLIC_CONFIG, PublicConfig } from "../config";
import { GardenRpcService } from "../rpc/garden-rpc.service";
import { SessionStore, type Session } from "./session-store";
@Injectable()
export class AuthService {
  private readonly verifier: ModuleJwtVerifier;
  constructor(
    private readonly erp: GravumRpcClient,
    private readonly core: GardenRpcService,
    readonly sessions: SessionStore,
    @Inject(PUBLIC_CONFIG) config: PublicConfig,
  ) {
    this.verifier = new ModuleJwtVerifier(erp, config);
  }
  async login(
    input: z.infer<typeof LoginInputSchema>,
    ip: string,
    userAgent?: string,
  ) {
    await this.sessions.throttle(ip, input.login);
    const result = await this.erp.login({
      ...input,
      ip,
      userAgent: userAgent?.slice(0, 512),
    });
    return this.openSession(result);
  }
  private async openSession(
    result: z.infer<typeof import("@311/gravum-contracts").LoginResultSchema>,
  ) {
    if (result.status === "mfa_required") return result;
    try {
      const record = await this.record(result.tokens);
      const profile = (await this.core.profile(record.accessToken)).data;
      const id = await this.sessions.create(record);
      return {
        status: "authenticated" as const,
        id,
        profile,
        csrfToken: record.csrfToken,
        sessionExpiresAt: record.sessionExpiresAt,
      };
    } catch (e) {
      await this.erp.logout(result.tokens.accessToken).catch(() => undefined);
      throw e;
    }
  }
  async register(
    input: z.infer<typeof import("@311/gravum-contracts").RegisterInputSchema>,
    ip: string,
    userAgent?: string,
  ) {
    await this.sessions.throttleAction("register", ip, input.email);
    const result = await this.erp.register({
      ...input,
      ip,
      userAgent: userAgent?.slice(0, 512),
    });
    return this.openSession(result);
  }
  async account(id: string) {
    return this.erp.account((await this.current(id)).accessToken);
  }
  async resendEmail(id: string, ip: string) {
    const session = await this.current(id);
    await this.sessions.throttleAction("resend", ip, session.principalId);
    return this.erp.resendEmail(session.accessToken);
  }
  async verifyEmail(
    input: z.infer<
      typeof import("@311/gravum-contracts").EmailTokenInputSchema
    >,
    ip: string,
  ) {
    await this.sessions.throttleAction("verify", ip, input.token);
    return this.erp.verifyEmail(input);
  }
  async verifyEmailCode(
    id: string,
    input: z.infer<typeof import("@311/gravum-contracts").EmailCodeInputSchema>,
    ip: string,
  ) {
    const session = await this.current(id);
    await this.sessions.throttleAction("verify-code", ip, session.principalId);
    return this.erp.verifyEmailCode(session.accessToken, input);
  }
  async requestReset(
    input: z.infer<typeof import("@311/gravum-contracts").EmailInputSchema>,
    ip: string,
  ) {
    await this.sessions.throttleAction("reset-request", ip, input.email);
    return this.erp.requestReset(input);
  }
  async confirmReset(
    input: z.infer<
      typeof import("@311/gravum-contracts").ResetPasswordInputSchema
    >,
    ip: string,
  ) {
    await this.sessions.throttleAction("reset-confirm", ip, input.token);
    return this.erp.confirmReset(input);
  }
  private async record(tokens: Tokens, previous?: Session): Promise<Session> {
    const claims = await this.verifier.verify(tokens.accessToken);
    if (
      previous &&
      (claims.sub !== previous.principalId ||
        claims.sid !== previous.erpSessionId ||
        tokens.sessionExpiresAt !== previous.sessionExpiresAt)
    )
      throw rpcError("INVALID_UPSTREAM_RESPONSE");
    if (Date.parse(tokens.sessionExpiresAt) <= Date.now())
      throw rpcError("UNAUTHENTICATED");
    return {
      ...tokens,
      csrfToken: previous?.csrfToken ?? randomBytes(32).toString("hex"),
      accessExpiresAt: claims.exp * 1000,
      principalId: claims.sub,
      erpSessionId: claims.sid,
      revision: (previous?.revision ?? -1) + 1,
      state: "ready",
    };
  }
  async current(id: string, forceRefresh = false) {
    const observed = await this.sessions.get(id);
    // A concurrent owner may be rotating; wait for it before deciding whether to rotate again.
    if (
      !forceRefresh &&
      observed.state === "ready" &&
      observed.accessExpiresAt > Date.now() + 30_000
    )
      return observed;
    return this.sessions.withLock(id, async (current, save) => {
      if (
        current.revision !== observed.revision ||
        (!forceRefresh && current.accessExpiresAt > Date.now() + 30_000)
      )
        return current;
      // Persist uncertainty before the non-idempotent ERP call. A crashed worker must not reuse this refresh token.
      await save({ ...current, state: "refreshing" });
      try {
        const tokens = await this.erp.refresh(current.refreshToken);
        const next = await this.record(tokens, current);
        await save(next);
        return next;
      } catch (e) {
        await this.sessions.remove(id).catch(() => undefined);
        throw e;
      }
    });
  }
  async me(id: string, refresh = false) {
    const session = await this.current(id, refresh);
    const profile = (await this.core.profile(session.accessToken)).data;
    return {
      profile,
      csrfToken: session.csrfToken,
      sessionExpiresAt: session.sessionExpiresAt,
    };
  }
  async logout(id: string) {
    try {
      await this.current(id);
      await this.sessions.withLock(id, async (session) => {
        try {
          await this.erp.logout(session.accessToken);
        } finally {
          await this.sessions.remove(id);
        }
      });
    } finally {
      // Also invalidate locally when ERP is unreachable; never report remote logout as successful.
      await this.sessions.remove(id);
    }
  }
}
