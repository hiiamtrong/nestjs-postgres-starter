import { ApiProperty } from '@nestjs/swagger';
import { Expose } from 'class-transformer';
import { UserStatus } from 'src/user/entities/user.entity';

export class UserOutput {
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
  createdAt: string;

  @Expose()
  @ApiProperty()
  updatedAt: string;
}
