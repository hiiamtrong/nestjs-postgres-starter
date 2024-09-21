import { SnowflakeIdColumn } from 'src/shared/decorators/snowflake-id.decorator';
import {
  Column,
  CreateDateColumn,
  DeleteDateColumn,
  Entity,
  Unique,
  UpdateDateColumn,
} from 'typeorm';

export enum UserStatus {
  PENDING = 'pending',
  ACTIVE = 'active',
  INACTIVE = 'inactive',
}

@Entity('users')
export class User {
  @SnowflakeIdColumn()
  id: number;

  @Unique('email', ['email'])
  @Column({ length: 200 })
  email: string;

  @Column({ length: 200 })
  password: string;

  @Column({ type: 'enum', enum: UserStatus, default: UserStatus.PENDING })
  status: UserStatus;

  @Column({ type: 'jsonb', nullable: true })
  metadata: Record<string, any>;

  @Column({ name: 'updated_by', nullable: true })
  updatedBy: number;

  @Column('boolean', { name: 'is_deleted', default: false })
  isDeleted: boolean;

  @Column({ name: 'deleted_by', nullable: true })
  deletedBy: number;

  @CreateDateColumn({ name: 'created_at', nullable: true })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', nullable: true })
  updatedAt: Date;

  @DeleteDateColumn({ name: 'deleted_at', nullable: true })
  deletedAt: Date;
}
