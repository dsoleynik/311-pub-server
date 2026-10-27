import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Post,
  Req,
  Res,
  HttpCode,
} from "@nestjs/common";
import { Response } from "express";
import { z } from "zod";
import {
  LoginInputSchema,
  RegisterInputSchema,
  EmailInputSchema,
  EmailTokenInputSchema,
  EmailCodeInputSchema,
  ResetPasswordInputSchema,
} from "@311/gravum-contracts";
import { AuthService } from "./auth.service";
import { BrowserRequestSecurity } from "./browser-request-security";
import { ContextRequest } from "../http/request-context";
@Controller()
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly browser: BrowserRequestSecurity,
  ) {}
  @Post("auth/login")
  @HttpCode(200)
  async login(
    @Body() raw: unknown,
    @Req() req: ContextRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    this.browser.origin(req);
    if (!req.is("application/json")) throw new BadRequestException();
    const input = LoginInputSchema.safeParse(raw);
    if (!input.success) throw new BadRequestException();
    const result = await this.auth.login(
      input.data,
      req.ip ?? "",
      req.headers["user-agent"],
    );
    if (result.status === "mfa_required")
      return { ok: true, requestId: req.garden.requestId, data: result };
    res.cookie(this.browser.cookieName, result.id, {
      ...this.browser.cookieOptions(),
      expires: new Date(result.sessionExpiresAt),
    });
    const { id: _id, ...data } = result;
    return { ok: true, requestId: req.garden.requestId, data };
  }
  @Post("auth/register")
  @HttpCode(200)
  async register(
    @Body() raw: unknown,
    @Req() req: ContextRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const input = this.input(RegisterInputSchema, raw, req);
    const result = await this.auth.register(
      input,
      req.ip ?? "",
      req.headers["user-agent"],
    );
    if (result.status === "mfa_required")
      return { ok: true, requestId: req.garden.requestId, data: result };
    res.cookie(this.browser.cookieName, result.id, {
      ...this.browser.cookieOptions(),
      expires: new Date(result.sessionExpiresAt),
    });
    const { id: _id, ...data } = result;
    return { ok: true, requestId: req.garden.requestId, data };
  }
  @Get("auth/account")
  async account(@Req() req: ContextRequest) {
    return {
      ok: true,
      requestId: req.garden.requestId,
      data: await this.auth.account(this.browser.id(req)),
    };
  }
  @Post("auth/email/resend")
  @HttpCode(200)
  async resend(@Req() req: ContextRequest) {
    const id = this.browser.id(req);
    await this.browser.csrf(req, id);
    return {
      ok: true,
      requestId: req.garden.requestId,
      data: await this.auth.resendEmail(id, req.ip ?? ""),
    };
  }
  @Post("auth/email/verify")
  @HttpCode(200)
  async verifyEmail(@Body() raw: unknown, @Req() req: ContextRequest) {
    return {
      ok: true,
      requestId: req.garden.requestId,
      data: await this.auth.verifyEmail(
        this.input(EmailTokenInputSchema, raw, req),
        req.ip ?? "",
      ),
    };
  }
  @Post("auth/email/verify-code")
  @HttpCode(200)
  async verifyEmailCode(@Body() raw: unknown, @Req() req: ContextRequest) {
    const id = this.browser.id(req);
    await this.browser.csrf(req, id);
    return {
      ok: true,
      requestId: req.garden.requestId,
      data: await this.auth.verifyEmailCode(
        id,
        this.input(EmailCodeInputSchema, raw, req),
        req.ip ?? "",
      ),
    };
  }
  @Post("auth/password-reset/request")
  @HttpCode(200)
  async requestReset(@Body() raw: unknown, @Req() req: ContextRequest) {
    return {
      ok: true,
      requestId: req.garden.requestId,
      data: await this.auth.requestReset(
        this.input(EmailInputSchema, raw, req),
        req.ip ?? "",
      ),
    };
  }
  @Post("auth/password-reset/confirm")
  @HttpCode(200)
  async confirmReset(
    @Body() raw: unknown,
    @Req() req: ContextRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const data = await this.auth.confirmReset(
      this.input(ResetPasswordInputSchema, raw, req),
      req.ip ?? "",
    );
    // The account's ERP sessions are revoked; discard the browser cookie too.
    res.clearCookie(this.browser.cookieName, this.browser.cookieOptions());
    return { ok: true, requestId: req.garden.requestId, data };
  }
  private input<T>(schema: z.ZodType<T>, raw: unknown, req: ContextRequest): T {
    this.browser.origin(req);
    if (!req.is("application/json")) throw new BadRequestException();
    const input = schema.safeParse(raw);
    if (!input.success) throw new BadRequestException();
    return input.data;
  }
  @Get(["auth/session", "me"])
  async me(@Req() req: ContextRequest) {
    return {
      ok: true,
      requestId: req.garden.requestId,
      data: await this.auth.me(this.browser.id(req)),
    };
  }
  @Post("auth/refresh")
  @HttpCode(200)
  async refresh(@Req() req: ContextRequest) {
    const id = this.browser.id(req);
    await this.browser.csrf(req, id);
    return {
      ok: true,
      requestId: req.garden.requestId,
      data: await this.auth.me(id, true),
    };
  }
  @Post("auth/logout")
  @HttpCode(200)
  async logout(
    @Req() req: ContextRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const id = this.browser.id(req);
    await this.browser.csrf(req, id);
    try {
      await this.auth.logout(id);
    } finally {
      res.clearCookie(this.browser.cookieName, this.browser.cookieOptions());
    }
    return {
      ok: true,
      requestId: req.garden.requestId,
      data: { success: true },
    };
  }
}
