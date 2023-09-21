import {
  ExecutionContext,
  ForbiddenException,
  createParamDecorator,
} from "@nestjs/common";
import { Jwt, uuid } from "@tmw-universe/tmw-universe-types";

export const UserId = createParamDecorator(
  (_: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const userId = (request?.user as Jwt)?.userId as uuid;
    if (!userId || typeof userId !== "string") throw new ForbiddenException();
    return userId;
  }
);
