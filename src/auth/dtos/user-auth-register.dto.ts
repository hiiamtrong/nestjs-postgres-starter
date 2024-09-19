import { ApiProperty } from '@nestjs/swagger';
import { Expose } from 'class-transformer';
import { IsNotEmpty, IsString, Length, MaxLength } from 'class-validator';
import { UserStatus } from 'src/user/entities/user.entity';

export class UserRegisterInput {
  @ApiProperty()
  @IsNotEmpty()
  @Length(7, 15)
  @IsString()
  phone: string;

  @ApiProperty()
  @MaxLength(50)
  @IsString()
  @IsNotEmpty()
  username: string;

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
  phone: string;

  @Expose()
  @ApiProperty()
  username: string;

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
  balance: number;

  @Expose()
  @ApiProperty()
  lockedBalance: number;

  @Expose()
  @ApiProperty()
  pendingBalance: number;

  @Expose()
  @ApiProperty()
  createdAt: string;

  @Expose()
  @ApiProperty()
  updatedAt: string;
}
