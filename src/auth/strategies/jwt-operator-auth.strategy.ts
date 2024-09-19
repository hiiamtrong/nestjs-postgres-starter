import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PermissionService } from 'src/permission/permission.service';
import { AppConfigService } from 'src/shared/configs/config.service';
import { createRequestContext } from 'src/shared/request-context/util';

import {
  AuthStrategyValidationOutput,
  STRATEGY_JWT_OPERATOR_AUTH,
} from '../constants/strategy.constant';

@Injectable()
export class JwtOperatorAuthStrategy extends PassportStrategy(
  Strategy,
  STRATEGY_JWT_OPERATOR_AUTH,
) {
  constructor(
    private readonly config: AppConfigService,
    private readonly permissionService: PermissionService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.jwt.publicKey,
      algorithms: ['RS256'],
      passReqToCallback: true,
    });
  }

  // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
  async validate(
    req: Request,
    payload: any,
  ): Promise<AuthStrategyValidationOutput> {
    // Passport automatically creates a user object, based on the value we return from the validate() method,
    // and assigns it to the Request object as req.user
    const ctx = createRequestContext(req);
    const { role, permissions } =
      await this.permissionService.getOperatorPermissions(ctx, payload.sub);
    return {
      id: payload.sub,
      email: payload.email,
      phone: payload.phone,
      username: payload.username,
      role,
      permissions,
    };
  }
}
