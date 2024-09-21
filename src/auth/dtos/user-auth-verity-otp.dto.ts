import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';
import { UserOutput } from 'src/user/dtos/user-output.dto';

export class UserAuthVerityOtpInput {
  @IsString()
  @IsNotEmpty()
  @ApiProperty()
  readonly otp: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty()
  @IsEmail()
  readonly email: string;
}

export class UserAuthVerityOtpOutput extends UserOutput {}
