import { ApiProperty } from '@nestjs/swagger';
import { Expose } from 'class-transformer';

export class OperatorAuthTokenOutput {
  @Expose()
  @ApiProperty()
  accessToken: string;

  @Expose()
  @ApiProperty()
  refreshToken: string;
}

export class OperatorAccessTokenClaims {
  @Expose()
  id: number;
  @Expose()
  email: string;
}

export class OperatorRefreshTokenClaims {
  id: number;
}
