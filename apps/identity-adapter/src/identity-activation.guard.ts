import { CanActivate, ExecutionContext, Injectable, SetMetadata } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { IdentityActivationService } from "./identity-activation.service.js";

export const activationProbe = "identity:activation-probe";
/** Only health handlers may use this marker; path spelling never grants an exemption. */
export const ActivationProbe = () => SetMetadata(activationProbe, true);
@Injectable()
export class IdentityActivationGuard implements CanActivate {
  constructor(private readonly activation: IdentityActivationService, private readonly reflector: Reflector) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (!this.activation.explicit || this.reflector.getAllAndOverride<boolean>(activationProbe, [context.getHandler(), context.getClass()])) return true;
    await this.activation.assertOpen();
    return true;
  }
}
