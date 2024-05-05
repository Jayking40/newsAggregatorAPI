/* eslint-disable prettier/prettier */
import { Injectable, NotFoundException } from '@nestjs/common';
import { User } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}

  async createUser(
    username: string,
    email: string,
    password: string,
  ): Promise<User> {
    return await this.prisma.user.create({
      data: {
        username,
        email,
        password,
      },
    });
  }

  async findUserByEmail(email: string): Promise<User> {
    return await this.prisma.user.findUnique({
      where: {
        email: email,
      },
    });
  }

  sanitizeUser(user: User): Partial<User> {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, ...sanitizedUser } = user;
    return sanitizedUser;
  }

  async findUserByUsername(username: string): Promise<User> {
    return await this.prisma.user.findUnique({
      where: { username },
    });
  }

  async validateUser(email: string, password: string): Promise<User | null> {
    const user = await this.prisma.user.findUnique({ where: { email } });

    if (!user) {
      return null;
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return null;
    }

    return user;
  }

  async deleteUser(userId: string): Promise<void> {
    const deletedUser = await this.prisma.user.delete({
      where: { id: userId },
    });
    if (!deletedUser) {
      throw new NotFoundException('User not found');
    }
  }

  async addToFavorites(userId: string, article: any[]): Promise<string> {
    try {
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
        select: { favorite: true }, // Include the current favorite articles
      });
  
      if (!user) {
        throw new Error('User not found');
      }
  
      let updatedFavorite: any[]; // Declare updatedFavorite variable
  
      // Check if user.favorite is an array before spreading it
      if (Array.isArray(user.favorite)) {
        updatedFavorite = [...user.favorite, article];
      } else {
        updatedFavorite = [article];
      }
  
      // Update the user with the updated list of favorite articles
      await this.prisma.user.update({
        where: { id: userId },
        data: {
          favorite: {
            set: updatedFavorite,
          },
        },
      });
  
      return 'Article added to favorites successfully';
    } catch (error) {
      throw new Error(`Failed to add article to favorites: ${error.message}`);
    }
  }

  async getFavorites(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new Error('User not found');
    }
    return user.favorite;
  }
}
