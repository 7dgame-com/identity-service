import { describe, expect, it } from "vitest";
import { calculateEffectivePermissions, createIamPermissionPolicySnapshot } from "../src/iam-permission-model.js";

describe("IAM permission policy candidate", () => {
  const policy = createIamPermissionPolicySnapshot({
    items: [
      { name: "admin", type: "role", description: "Administrator" },
      { name: "manager", type: "role" },
      { name: "plugin.open", type: "permission" },
      { name: "course.manage", type: "permission" },
      { name: "profile.read", type: "permission" }
    ],
    relations: [
      { parent: "admin", child: "manager" },
      { parent: "manager", child: "plugin.open" },
      { parent: "admin", child: "course.manage" }
    ]
  });

  it("has a stable checksum independent of item and relation order", () => {
    const reordered = createIamPermissionPolicySnapshot({
      items: [...policy.permissions, ...policy.roles].reverse(),
      relations: [...policy.relations].reverse()
    });

    expect(reordered.checksum).toBe(policy.checksum);
  });

  it("expands inherited roles and direct permissions without legacy reads", () => {
    expect(calculateEffectivePermissions(policy, ["admin", "profile.read"])).toEqual({
      permissions: ["course.manage", "plugin.open", "profile.read"],
      unknownAssignments: []
    });
  });

  it("fails closed for unknown assignments", () => {
    expect(calculateEffectivePermissions(policy, ["unknown-role"])).toEqual({
      permissions: [],
      unknownAssignments: ["unknown-role"]
    });
  });

  it("rejects invalid and cyclic relationships before a candidate can be stored", () => {
    expect(() =>
      createIamPermissionPolicySnapshot({
        items: [{ name: "admin", type: "role" }],
        relations: [{ parent: "admin", child: "missing" }]
      })
    ).toThrow("unknown item");

    expect(() =>
      createIamPermissionPolicySnapshot({
        items: [
          { name: "admin", type: "role" },
          { name: "manager", type: "role" }
        ],
        relations: [
          { parent: "admin", child: "manager" },
          { parent: "manager", child: "admin" }
        ]
      })
    ).toThrow("contains a cycle");
  });
});
