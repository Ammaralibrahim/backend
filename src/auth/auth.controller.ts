import { Controller, Post, Body, HttpException, HttpStatus, Put, Get, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { User } from './schemas/user.schema';
import { JwtAuthGuard } from './jwt-auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(@Body() user: User) {
    try {
      const token = await this.authService.registerAndLogin(user);
      return { message: 'Registration successful', token };
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.BAD_REQUEST);
    }
  }

  @Post('login')
  async login(@Body('email') email: string, @Body('password') password: string): Promise<any> {
    try {
      const token = await this.authService.login(email, password);
      if (!token) {
        throw new HttpException('Invalid email or password', HttpStatus.UNAUTHORIZED);
      }
      return { message: 'Login successful', token };
    } catch (error) {
      throw new HttpException(error.message || 'Login failed', HttpStatus.UNAUTHORIZED);
    }
  }

  @Post('verify')
  async verify(@Body('token') token: string): Promise<any> {
    const isValid = await this.authService.verifyToken(token);
    if (!isValid) {
      throw new HttpException('Invalid token', HttpStatus.UNAUTHORIZED);
    }
    return { message: 'Token is valid' };
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  async getProfile(@Req() req): Promise<any> {
    try {
      const user = await this.authService.getUserById(req.user.userId);
      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }
      return { user };
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.BAD_REQUEST);
    }
  }

  
  @Put('send-verification-code')
  async sendVerificationCode(@Body('email') email: string): Promise<any> {
    try {
      await this.authService.sendVerificationCode(email);
      return { message: 'Verification code sent' };
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.BAD_REQUEST);
    }
  }

  @Put('verify-and-reset-password')
  async verifyAndResetPassword(
    @Body('email') email: string,
    @Body('verificationCode') verificationCode: string,
    @Body('newPassword') newPassword: string
  ): Promise<any> {
    try {
      await this.authService.verifyAndResetPassword(email, verificationCode, newPassword);
      return { message: 'Password reset successful' };
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.BAD_REQUEST);
    }
  }
  
  
}
