import { ApiProperty } from '@nestjs/swagger';
import { Expose } from 'class-transformer';
import {
  IsEmail,
  IsNotEmpty,
  IsString,
  Length,
  MaxLength,
} from 'class-validator';
import { UserStatus } from 'src/user/entities/user.entity';

export class UserRegisterInput {
  @ApiProperty()
  @IsNotEmpty()
  @IsEmail()
  @MaxLength(200)
  email: string;

  @ApiProperty()
  @IsNotEmpty()
  @Length(8, 16)
  @IsString()
  password: string;
}

export class UserRegisterOutput {
  @Expose()
  @ApiProperty()
  id: number;

  @Expose()
  @ApiProperty()
  email: string;

  @Expose()
  @ApiProperty()
  status: UserStatus;

  @Expose()
  @ApiProperty()
  metadata: Record<string, any>;

  @Expose()
  @ApiProperty()
  createdAt: string;

  @Expose()
  @ApiProperty()
  updatedAt: string;
}
