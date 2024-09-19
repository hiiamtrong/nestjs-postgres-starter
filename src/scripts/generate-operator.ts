import { NestFactory } from '@nestjs/core';
import * as rl from 'readline/promises';
import { AppModule } from 'src/app.module';
import {
  Operator,
  OperatorStatus,
} from 'src/operator/entities/operator.entity';
import { OperatorRepository } from 'src/operator/operator.repository';
import { OperatorService } from 'src/operator/operator.service';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const operatorRepository = app.get(OperatorRepository);
  const operatorService = app.get(OperatorService);

  // get user input

  const readline = rl.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const email = await readline.question('Enter email: ');

  const randomPassword = operatorService.generateRandomPassword();
  const newOperator = new Operator();
  newOperator.email = email;
  newOperator.status = OperatorStatus.ACTIVE;
  newOperator.password = await operatorService.hashPassword(randomPassword);
  newOperator.metadata = {};

  await operatorRepository.save(newOperator);
  // Print new operator details
  console.log(`New operator created with email: ${email}`);
  console.log(`Password: ${randomPassword}`);

  await app.close();

  process.exit(0);
}

bootstrap();
