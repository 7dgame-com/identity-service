import "reflect-metadata";
import { INestApplication } from "@nestjs/common";
import { Test } from "@nestjs/testing";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AppModule } from "../src/app.module.js";
import { LegacyIdentityReader } from "../src/legacy-identity.reader.js";
import { assertReadonlySql } from "../src/readonly-write.guard.js";

class FakeLegacyIdentityReader {
  async health() {
    return "not_configured";
  }

  async diagnostics() {
    return {
      legacyDatabaseConfigured: false,
      tables: {
        user: false,
        user_info: false,
        auth_item: false,
        auth_assignment: false,
        organization: false,
        user_organization: false
      }
    };
  }

  async getUserById(id: number) {
    if (id !== 24) {
      return null;
    }

    return {
      id: 24,
      username: "guanfei",
      email: "ogre3d@163.com",
      status: 10,
      nickname: "babamama",
      emailVerifiedAt: 1772210253,
      createdAt: 1558664856,
      updatedAt: 1763711034,
      userInfo: { locale: "zh-CN" },
      roles: ["admin"],
      organizations: [{ id: 1, name: "test-university", title: "测试大学", createdAt: 1, updatedAt: 1 }],
      source: "legacy" as const
    };
  }

  async listRoles() {
    return [{ name: "admin", description: "Administrator", createdAt: 1, updatedAt: 1 }];
  }

  async listOrganizations() {
    return [{ id: 1, name: "test-university", title: "测试大学", createdAt: 1, updatedAt: 1 }];
  }
}

describe("identity-adapter readonly API", () => {
  let app: INestApplication;

  beforeEach(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule]
    })
      .overrideProvider(LegacyIdentityReader)
      .useClass(FakeLegacyIdentityReader)
      .compile();

    app = moduleRef.createNestApplication();
    await app.init();
  });

  afterEach(async () => {
    await app.close();
  });

  it("returns health in readonly mode", async () => {
    const response = await request(app.getHttpServer()).get("/health").expect(200);

    expect(response.body).toMatchObject({
      status: "ok",
      service: "identity-adapter",
      mode: "readonly",
      dependencies: {
        legacyDatabase: "not_configured"
      }
    });
  });

  it("returns safe empty JWKS by default", async () => {
    const response = await request(app.getHttpServer()).get("/jwks.json").expect(200);

    expect(response.body).toEqual({ keys: [] });
  });

  it("returns readonly legacy user details", async () => {
    const response = await request(app.getHttpServer()).get("/admin/users/24").expect(200);

    expect(response.body.data).toMatchObject({
      id: 24,
      username: "guanfei",
      roles: ["admin"],
      organizations: [{ name: "test-university", title: "测试大学" }],
      source: "legacy"
    });
  });

  it("returns roles and organizations", async () => {
    const roles = await request(app.getHttpServer()).get("/admin/roles").expect(200);
    const organizations = await request(app.getHttpServer()).get("/admin/organizations").expect(200);

    expect(roles.body.data).toEqual([{ name: "admin", description: "Administrator", createdAt: 1, updatedAt: 1 }]);
    expect(organizations.body.data).toEqual([
      { id: 1, name: "test-university", title: "测试大学", createdAt: 1, updatedAt: 1 }
    ]);
  });

  it("does not implement token introspection in phase 3", async () => {
    await request(app.getHttpServer())
      .get("/userinfo")
      .set("Authorization", "Bearer legacy-token")
      .expect(501);
  });

  it("blocks write-like SQL statements", () => {
    expect(() => assertReadonlySql("SELECT * FROM user")).not.toThrow();
    expect(() => assertReadonlySql("UPDATE user SET status = 0")).toThrow(/blocked write-like SQL/);
  });
});

