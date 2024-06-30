import { Controller, Post, Body, HttpException, HttpStatus } from '@nestjs/common';
import { AuthService } from './auth.service';
import { User } from './schemas/user.schema';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(@Body() user: User) {
    try {
      const newUser = await this.authService.register(user);
      return { message: 'Kayıt başarılı', user: newUser };
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.BAD_REQUEST);
    }
  }

  @Post('login')
  async login(@Body('email') email: string, @Body('password') password: string): Promise<any> {
    try {
      const token = await this.authService.login(email, password);
      if (!token) {
        throw new HttpException('Geçersiz email veya şifre', HttpStatus.UNAUTHORIZED);
      }
      console.log('oturum açıldı.');

      return { message: 'Giriş başarılı', token };
    } catch (error) {
      throw new HttpException(error.message || 'Giriş başarısız', HttpStatus.UNAUTHORIZED);
    }
  }

  @Post('verify')
  async verify(@Body('token') token: string): Promise<any> {
    const isValid = await this.authService.verifyToken(token);
    if (!isValid) {
      throw new HttpException('Geçersiz token', HttpStatus.UNAUTHORIZED);
    }
    return { message: 'Token geçerli' };
  }
  
}
