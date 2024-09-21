import { Snowflake } from 'nodejs-snowflake';
import { BeforeInsert, PrimaryColumn } from 'typeorm';

const snowflake = new Snowflake();

export function SnowflakeIdColumn() {
  return function (target: any, propertyKey: string) {
    PrimaryColumn('bigint')(target, propertyKey);

    BeforeInsert()(target, `${propertyKey}Generator`);
    Object.defineProperty(target, `${propertyKey}Generator`, {
      value: function () {
        if (!this[propertyKey]) {
          this[propertyKey] = snowflake.getUniqueID().toString();
        }
      },
      writable: true,
    });
  };
}
