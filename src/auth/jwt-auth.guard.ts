import { Injectable, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor() {
    super();
  }

  canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    
    // JWT'den gelen kullanıcı bilgilerini kontrol et
    if (request.user && request.user.userId) {
      request.user = { userId: request.user.userId }; // JWT payload yapısına göre düzenle
    } else {
      throw new UnauthorizedException('Yetkisiz');
    }
    
    return super.canActivate(context);
  }
}
