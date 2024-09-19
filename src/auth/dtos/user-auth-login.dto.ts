import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, Length } from 'class-validator';

export class UserLoginInput {
  @IsNotEmpty()
  @ApiProperty()
  @IsString()
  @Length(7, 15)
  phone: string;

  @IsNotEmpty()
  @ApiProperty()
  @IsString()
  password: string;
}
