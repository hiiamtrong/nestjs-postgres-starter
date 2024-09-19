import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AppConfigService } from 'src/shared/configs/config.service';

import { STRATEGY_JWT_USER_REFRESH } from '../constants/strategy.constant';
import { UserRefreshTokenClaims } from '../dtos/user-auth-token.dto';

@Injectable()
export class JwtUserRefreshStrategy extends PassportStrategy(
  Strategy,
  STRATEGY_JWT_USER_REFRESH,
) {
  constructor(private readonly config: AppConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromBodyField('refreshToken'),
      secretOrKey: config.jwt.publicKey,
      algorithms: ['RS256'],
    });
  }

  // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
  async validate(payload: any): Promise<UserRefreshTokenClaims> {
    // Passport automatically creates a user object, based on the value we return from the validate() method,
    // and assigns it to the Request object as req.user
    return { id: payload.sub };
  }
}
