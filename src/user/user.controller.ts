/* eslint-disable prettier/prettier */
import { BadRequestException, Body, Controller, Delete, Get, HttpStatus, NotFoundException, Param, Post, Req, Res, UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { CreateUserDto } from './dto/user.dto';
import { JwtService } from 'src/jwt/jwt.service';
import * as bcrypt from 'bcryptjs';
import { AuthGuard } from 'src/auth.guard';

@Controller('user')
export class UserController {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
) {}

@Post('register')
async registerUser(@Body() createUserDto: CreateUserDto) {
  const { username, email, password } = createUserDto;

  // Check if email or username already exists
  const existingUserByEmail = await this.userService.findUserByEmail(email);
  const existingUserByUsername = await this.userService.findUserByUsername(username);

  if (existingUserByEmail) {
    throw new BadRequestException('Email is already registered');
  }

  if (existingUserByUsername) {
    throw new BadRequestException('Username is already taken');
  }

  // Create user
  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = await this.userService.createUser(username, email, hashedPassword);

  // Generate access token
  const accessToken = await this.jwtService.generateAccessToken(newUser);

  // Sanitize user object
  const sanitizedUser = this.userService.sanitizeUser(newUser);

  // Return user ID, access token, and sanitized user object
  return {
    userId: newUser.id,
    accessToken,
    user: sanitizedUser,
  };
}

  @Post('login')
  async loginUser(@Body() { email, password }) {
    const user = await this.userService.validateUser(email, password);

    if (!user) {
      throw new BadRequestException('Invalid email or password');
    }

    // Generate JWT tokens
    const accessToken = this.jwtService.generateAccessToken({ userId: user.id });
    const refreshToken = this.jwtService.generateRefreshToken({ userId: user.id });

    return { accessToken, refreshToken, email: user.email, username: user.username, userId: user.id };
  }

  @Delete('deleteUser/:id')
  async deleteUser(@Param('id') userId: string) {
    await this.userService.deleteUser(userId);
    return { message: 'User deleted successfully' };
  }

  @Post('refreshToken')
  async generateRefreshToken(@Body() payload: any) {
    const refreshToken = this.jwtService.generateRefreshToken(payload);
    return { refreshToken };
  }

  @UseGuards(AuthGuard)
  @Post('favorite')
  async addToUserFavorites(@Req() req: any, @Body() articleData: any, @Res() res) {
    try {
      const article = { ...articleData };
      const message = await this.userService.addToFavorites(req.user.id, article);
      res.status(HttpStatus.OK).json(message);
    } catch (error) {
      if (error instanceof NotFoundException) {
        res.status(HttpStatus.NOT_FOUND).json(error.message);
      } else {
        res.status(HttpStatus.BAD_REQUEST).json(error.message);
      }
    }
  }

  @UseGuards(AuthGuard)
  @Get('allFavorites')
  async getUserFavorites(@Res() res: any, @Req() req: any) {
    try {
      const favorites = await this.userService.getFavorites(req.user.id);
      res.status(HttpStatus.OK).json(favorites);
    } catch (error) {
      if (error instanceof NotFoundException) {
        res.status(HttpStatus.NOT_FOUND).json(error.message);
      } else {
        res.status(HttpStatus.BAD_REQUEST).json(error.message);
      }
    }
  }
}
