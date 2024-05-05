/* eslint-disable prettier/prettier */
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as jwt from 'jsonwebtoken';

@Injectable()
export class JwtService {
  private readonly accessTokenSecret = this.config.get('JWT_SECRET');
  private readonly refreshTokenSecret = this.config.get('JWT_RefreshSecret');

  constructor(private config: ConfigService) {}

  generateAccessToken(payload: any): string {
    return jwt.sign(payload, this.accessTokenSecret, { expiresIn: '1h' });
  }

  generateRefreshToken(payload: any): string {
    return jwt.sign(payload, this.refreshTokenSecret, { expiresIn: '7d' });
  }

  verifyToken(token: string, secret: string): any {
    return jwt.verify(token, secret);
  }
}
