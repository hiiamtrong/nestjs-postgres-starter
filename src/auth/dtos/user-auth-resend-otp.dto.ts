import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class UserAuthResendOtpInput {
  @IsString()
  @IsNotEmpty()
  @ApiProperty()
  @IsEmail()
  readonly email: string;
}
