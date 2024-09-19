import {
  Column,
  CreateDateColumn,
  DeleteDateColumn,
  UpdateDateColumn,
} from 'typeorm';

export class AppBaseEntity {
  @Column({ name: 'created_by' })
  createdBy: number;

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
