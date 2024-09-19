import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';
import { UserOutput } from 'src/user/dtos/user-output.dto';

export class UserAuthVerityOtpInput {
  @IsString()
  @IsNotEmpty()
  @ApiProperty()
  readonly otp: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty()
  readonly phone: string;
}

export class UserAuthVerityOtpOutput extends UserOutput {}
