import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class UserResetPasswordInput {
  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  phone: string;

  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  otp: string;

  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  password: string;
}
