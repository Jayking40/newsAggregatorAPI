/* eslint-disable prettier/prettier */
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { JwtService } from './jwt/jwt.service';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private readonly jwtService: JwtService, private config: ConfigService) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const authorizationHeader = request.headers['authorization'];

    if (!authorizationHeader) {
      return false;
    }

    const token = authorizationHeader.split(' ')[1];

    try {
      const decodedToken = this.jwtService.verifyToken(token, this.config.get('JWT_SECRET'));
      request.user = decodedToken;
      return true;
    } catch (error) {
      return false;
    }
  }
}