import { MigrationInterface, QueryRunner } from 'typeorm';

export class Init1726764750238 implements MigrationInterface {
    name = 'Init1726764750238';

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
                "id" SERIAL NOT NULL,
                "username" character varying(200) NOT NULL,
                "phone" character varying(200) NOT NULL,
                "email" character varying(200),
                "password" character varying NOT NULL,
                "status" "public"."users_status_enum" NOT NULL DEFAULT 'pending',
                "metadata" jsonb,
                "balance" numeric(10, 2) NOT NULL DEFAULT '0',
                "locked_balance" numeric(10, 2) NOT NULL DEFAULT '0',
                "pending_balance" numeric(10, 2) NOT NULL DEFAULT '0',
                "updated_by" integer,
                "is_deleted" boolean NOT NULL DEFAULT false,
                "deleted_by" integer,
                "created_at" TIMESTAMP DEFAULT now(),
                "updated_at" TIMESTAMP DEFAULT now(),
                "deleted_at" TIMESTAMP,
                CONSTRAINT "username" UNIQUE ("username"),
                CONSTRAINT "phone" UNIQUE ("phone"),
                CONSTRAINT "PK_a3ffb1c0c8416b9fc6f907b7433" PRIMARY KEY ("id")
            )
        `);
        await queryRunner.query(`
            CREATE UNIQUE INDEX "IDX_65cbf5fcb331619593ee334c7c" ON "users" ("email")
            WHERE email IS NOT NULL
        `);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`
            DROP INDEX "public"."IDX_65cbf5fcb331619593ee334c7c"
        `);
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
