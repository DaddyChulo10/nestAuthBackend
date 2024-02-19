import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from '../interfaces/jwt-plaload';
import { Observable } from 'rxjs';
import * as request from 'supertest';
import { AuthService } from '../auth.service';
// import { JwtPayload } from '../../../dist/auth/interfaces/jwt-plaload';

@Injectable()
export class AuthGuard implements CanActivate {

  constructor(private jwtService: JwtService, private authService: AuthService) { }

  async canActivate(context: ExecutionContext): Promise<boolean | null> {
    const request = context.switchToHttp().getRequest()
    const token = this.estractTokenFromHeader(request)
    if (!token) {
      throw new UnauthorizedException('No existe un Token')
    }

    try {
      const payload = await this.jwtService.verifyAsync<JwtPayload>(
        token, { secret: process.env.JWT_SEED }
      )
      const user = await this.authService.findUserById(payload.id)
      if (!user) throw new UnauthorizedException('El usuario no existe')
      if (!user.isActive) throw new UnauthorizedException('El usuario no esta activado')
      request['user'] = user
    } catch (error) {
      throw new UnauthorizedException('No tiene autorizacion')
    }
    return true;
  }

  private estractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
