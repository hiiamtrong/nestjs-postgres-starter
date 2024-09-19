import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ROLE } from 'src/auth/constants/role.constant';
import { AppConfigService } from 'src/shared/configs/config.service';

import {
  AuthStrategyValidationOutput,
  STRATEGY_JWT_USER_AUTH,
} from '../constants/strategy.constant';

@Injectable()
export class JwtUserAuthStrategy extends PassportStrategy(
  Strategy,
  STRATEGY_JWT_USER_AUTH,
) {
  constructor(private readonly config: AppConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.jwt.publicKey,
      algorithms: ['RS256'],
    });
  }

  // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
  async validate(payload: any): Promise<AuthStrategyValidationOutput> {
    // Passport automatically creates a user object, based on the value we return from the validate() method,
    // and assigns it to the Request object as req.user
    return {
      id: payload.sub,
      phone: payload.phone,
      username: payload.username,
      email: payload.email,
      role: ROLE.USER,
      permissions: new Set(),
    };
  }
}
