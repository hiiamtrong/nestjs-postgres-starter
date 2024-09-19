import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { OperatorRefreshTokenClaims } from 'src/auth/dtos/operator-auth-token.dto';
import { AppConfigService } from 'src/shared/configs/config.service';

import { STRATEGY_JWT_OPERATOR_REFRESH } from '../constants/strategy.constant';

@Injectable()
export class JwtOperatorRefreshStrategy extends PassportStrategy(
  Strategy,
  STRATEGY_JWT_OPERATOR_REFRESH,
) {
  constructor(private readonly config: AppConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromBodyField('refreshToken'),
      secretOrKey: config.jwt.publicKey,
      algorithms: ['RS256'],
    });
  }

  // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
  async validate(payload: any): Promise<OperatorRefreshTokenClaims> {
    // Passport automatically creates a user object, based on the value we return from the validate() method,
    // and assigns it to the Request object as req.user
    return { id: payload.sub };
  }
}
