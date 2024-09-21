import { MigrationInterface, QueryRunner } from 'typeorm';

export class Init1726889336706 implements MigrationInterface {
    name = 'Init1726889336706';

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`
            CREATE TYPE "public"."operators_status_enum" AS ENUM('pending', 'active', 'inactive')
        `);
        await queryRunner.query(`
            CREATE TABLE "operators" (
                "id" SERIAL NOT NULL,
                "email" character varying(200) NOT NULL,
                "password" character varying NOT NULL,
                "status" "public"."operators_status_enum" NOT NULL DEFAULT 'pending',
                "metadata" jsonb,
                "created_by" integer,
                "updated_by" integer,
                "is_deleted" boolean NOT NULL DEFAULT false,
                "deleted_by" integer,
                "created_at" TIMESTAMP DEFAULT now(),
                "updated_at" TIMESTAMP DEFAULT now(),
                CONSTRAINT "PK_3d02b3692836893720335a79d1b" PRIMARY KEY ("id")
            )
        `);
        await queryRunner.query(`
            CREATE UNIQUE INDEX "IDX_1570f3d85c3ff08bb99815897a" ON "operators" ("email")
        `);
        await queryRunner.query(`
            CREATE TYPE "public"."users_status_enum" AS ENUM('pending', 'active', 'inactive')
        `);
        await queryRunner.query(`
            CREATE TABLE "users" (
                "id" bigint NOT NULL,
                "email" character varying(200) NOT NULL,
                "password" character varying(200) NOT NULL,
                "status" "public"."users_status_enum" NOT NULL DEFAULT 'pending',
                "metadata" jsonb,
                "updated_by" integer,
                "is_deleted" boolean NOT NULL DEFAULT false,
                "deleted_by" integer,
                "created_at" TIMESTAMP DEFAULT now(),
                "updated_at" TIMESTAMP DEFAULT now(),
                "deleted_at" TIMESTAMP,
                CONSTRAINT "email" UNIQUE ("email"),
                CONSTRAINT "PK_a3ffb1c0c8416b9fc6f907b7433" PRIMARY KEY ("id")
            )
        `);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`
            DROP TABLE "users"
        `);
        await queryRunner.query(`
            DROP TYPE "public"."users_status_enum"
        `);
        await queryRunner.query(`
            DROP INDEX "public"."IDX_1570f3d85c3ff08bb99815897a"
        `);
        await queryRunner.query(`
            DROP TABLE "operators"
        `);
        await queryRunner.query(`
            DROP TYPE "public"."operators_status_enum"
        `);
    }
}
