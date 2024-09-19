import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';
import { OperatorOutput } from 'src/operator/dtos/operator.dto';

export class OperatorAuthVerityOtpInput {
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

export class OperatorAuthVerityOtpOutput extends OperatorOutput {}
