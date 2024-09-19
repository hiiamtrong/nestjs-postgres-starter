import { ApiProperty } from '@nestjs/swagger';
import { Expose } from 'class-transformer';

export class UserAuthTokenOutput {
  @Expose()
  @ApiProperty()
  accessToken: string;

  @Expose()
  @ApiProperty()
  refreshToken: string;
}

export class UserAccessTokenClaims {
  @Expose()
  id: number;
  @Expose()
  username: string;
  @Expose()
  phone: string;
  @Expose()
  email: string;
}

export class UserRefreshTokenClaims {
  id: number;
}
