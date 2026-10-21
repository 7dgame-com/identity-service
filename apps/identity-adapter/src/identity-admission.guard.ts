import { CanActivate, ExecutionContext, Injectable } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { activationProbe } from "./identity-activation.guard.js";
import { assertAdmissionRequest } from "./identity-admission.js";

/** Alternate bootstraps cannot silently serve a handler without the entry adapter. */
@Injectable()
export class IdentityAdmissionGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}
  canActivate(context: ExecutionContext): boolean {
    assertAdmissionRequest(
      this.reflector.getAllAndOverride<boolean>(activationProbe, [
        context.getHandler(),
        context.getClass(),
      ]) === true,
    );
    return true;
  }
}
