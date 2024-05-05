import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { JwtService } from 'src/jwt/jwt.service';

@Module({
  providers: [UserService, JwtService],
  controllers: [UserController],
})
export class UserModule {}
