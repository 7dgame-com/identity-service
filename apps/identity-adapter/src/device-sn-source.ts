import { ForbiddenException, HttpException, ServiceUnavailableException, UnauthorizedException } from "@nestjs/common";

export interface DeviceSnSource {
  authMethod: "device_sn";
  deviceSnId: number;
}

/** Absence is the existing ordinary session; partial/unknown provenance fails closed. */
export function deviceSnSource(authMethod: unknown, deviceSnId: unknown): DeviceSnSource | null {
  if (authMethod == null && deviceSnId == null) return null;
  if (authMethod !== "device_sn" || typeof deviceSnId !== "number" || !Number.isSafeInteger(deviceSnId) || deviceSnId <= 0) {
    throw new UnauthorizedException({ code: "DEVICE_SN_SOURCE_INVALID", message: "Device session source is invalid." });
  }
  return { authMethod, deviceSnId };
}

export function deviceSnClaims(payload: Record<string, unknown>): DeviceSnSource | null {
  if (!("auth_method" in payload) && !("device_sn_id" in payload)) return null;
  if (payload.auth_method == null || payload.device_sn_id == null) {
    throw new UnauthorizedException({ code: "DEVICE_SN_SOURCE_INVALID", message: "Device session source is incomplete." });
  }
  return deviceSnSource(payload.auth_method, payload.device_sn_id);
}

export function assertDeviceSnAccount(user: { status: number; roles: string[] }): void {
  if (user.status !== 10 || user.roles.some((role) => ["root", "admin", "manager"].includes(role))) {
    throw new UnauthorizedException({ code: "DEVICE_SN_ACCOUNT_INELIGIBLE", message: "Account is not eligible for device sessions." });
  }
}

export function denyDeviceSnCredentialDerivation(): never {
  throw new ForbiddenException({ code: "DEVICE_SN_CREDENTIAL_DERIVATION_FORBIDDEN", message: "Device sessions cannot create other login credentials." });
}

/** Stable source-aware errors also prevent the main backend's ordinary provider fallback. */
export function throwDeviceSnFailure(error: unknown): never {
  if (error instanceof HttpException) {
    const response = error.getResponse();
    if (typeof response === "object" && "code" in response && String(response.code).startsWith("DEVICE_SN_")) throw error;
    if ([401, 403].includes(error.getStatus())) {
      throw new UnauthorizedException({ code: "DEVICE_SN_UNAVAILABLE", message: "Device authorization is unavailable." });
    }
  }
  throw new ServiceUnavailableException({ code: "DEVICE_SN_VALIDATION_UNAVAILABLE", message: "Device authorization could not be verified." });
}
