import { createHash } from "node:crypto";

export type IamPolicyItemType = "role" | "permission";

export interface IamPolicyItemInput {
  name: string;
  type: IamPolicyItemType;
  description?: string | null;
}

export interface IamPolicyRelationInput {
  parent: string;
  child: string;
}

export interface IamPermissionPolicyInput {
  items: IamPolicyItemInput[];
  relations: IamPolicyRelationInput[];
}

export interface IamPermissionPolicySnapshot {
  checksum: string;
  roles: ReadonlyArray<IamPolicyItemInput>;
  permissions: ReadonlyArray<IamPolicyItemInput>;
  relations: ReadonlyArray<IamPolicyRelationInput>;
}

export interface IamEffectivePermissionResult {
  permissions: string[];
  unknownAssignments: string[];
}

/**
 * Produces a canonical, immutable candidate policy. The checksum is the policy version;
 * callers must create a new version instead of mutating an existing snapshot.
 */
export function createIamPermissionPolicySnapshot(input: IamPermissionPolicyInput): IamPermissionPolicySnapshot {
  const itemsByName = new Map<string, IamPolicyItemInput>();
  for (const rawItem of input.items) {
    const item = normalizeItem(rawItem);
    if (itemsByName.has(item.name)) {
      throw new Error(`Duplicate IAM policy item: ${item.name}`);
    }
    itemsByName.set(item.name, item);
  }

  const relations = deduplicateRelations(input.relations, itemsByName);
  assertAcyclic(relations);

  const items = [...itemsByName.values()].sort(compareItems);
  const canonicalRelations = [...relations].sort(compareRelations);
  const checksum = createHash("sha256")
    .update(
      JSON.stringify({
        items: items.map((item) => ({ name: item.name, type: item.type, description: item.description ?? null })),
        relations: canonicalRelations
      })
    )
    .digest("hex");

  return {
    checksum,
    roles: items.filter((item) => item.type === "role"),
    permissions: items.filter((item) => item.type === "permission"),
    relations: canonicalRelations
  };
}

/**
 * Computes permissions from one immutable candidate policy. Unknown assignments do not
 * grant anything, which keeps the candidate path fail-closed while it is still shadow-only.
 */
export function calculateEffectivePermissions(
  policy: IamPermissionPolicySnapshot,
  assignments: readonly string[]
): IamEffectivePermissionResult {
  const itemByName = new Map<string, IamPolicyItemInput>([
    ...policy.roles.map((item) => [item.name, item] as const),
    ...policy.permissions.map((item) => [item.name, item] as const)
  ]);
  const childrenByParent = new Map<string, string[]>();
  for (const relation of policy.relations) {
    const children = childrenByParent.get(relation.parent) ?? [];
    children.push(relation.child);
    childrenByParent.set(relation.parent, children);
  }

  const permissions = new Set<string>();
  const unknownAssignments: string[] = [];
  const visited = new Set<string>();
  const queue: string[] = [];
  for (const rawAssignment of assignments) {
    const assignment = rawAssignment.trim();
    if (!assignment) {
      continue;
    }
    if (!itemByName.has(assignment)) {
      unknownAssignments.push(assignment);
      continue;
    }
    queue.push(assignment);
  }

  while (queue.length > 0) {
    const current = queue.shift()!;
    if (visited.has(current)) {
      continue;
    }
    visited.add(current);

    const item = itemByName.get(current);
    if (!item) {
      continue;
    }
    if (item.type === "permission") {
      permissions.add(item.name);
    }
    for (const child of childrenByParent.get(item.name) ?? []) {
      if (!visited.has(child)) {
        queue.push(child);
      }
    }
  }

  return {
    permissions: [...permissions].sort(),
    unknownAssignments: [...new Set(unknownAssignments)].sort()
  };
}

function normalizeItem(input: IamPolicyItemInput): IamPolicyItemInput {
  const name = input.name.trim();
  if (!name) {
    throw new Error("IAM policy item name is required");
  }
  if (input.type !== "role" && input.type !== "permission") {
    throw new Error(`Unsupported IAM policy item type: ${String(input.type)}`);
  }
  return {
    name,
    type: input.type,
    description: input.description?.trim() || null
  };
}

function deduplicateRelations(
  input: readonly IamPolicyRelationInput[],
  itemsByName: ReadonlyMap<string, IamPolicyItemInput>
): IamPolicyRelationInput[] {
  const relations = new Map<string, IamPolicyRelationInput>();
  for (const rawRelation of input) {
    const parent = rawRelation.parent.trim();
    const child = rawRelation.child.trim();
    if (!parent || !child) {
      throw new Error("IAM policy relation parent and child are required");
    }
    if (!itemsByName.has(parent) || !itemsByName.has(child)) {
      throw new Error(`IAM policy relation references an unknown item: ${parent} -> ${child}`);
    }
    relations.set(`${parent}\u0000${child}`, { parent, child });
  }
  return [...relations.values()];
}

function assertAcyclic(relations: readonly IamPolicyRelationInput[]): void {
  const childrenByParent = new Map<string, string[]>();
  for (const relation of relations) {
    const children = childrenByParent.get(relation.parent) ?? [];
    children.push(relation.child);
    childrenByParent.set(relation.parent, children);
  }
  const visiting = new Set<string>();
  const visited = new Set<string>();

  const visit = (name: string): void => {
    if (visited.has(name)) {
      return;
    }
    if (visiting.has(name)) {
      throw new Error(`IAM policy relation contains a cycle at: ${name}`);
    }
    visiting.add(name);
    for (const child of childrenByParent.get(name) ?? []) {
      visit(child);
    }
    visiting.delete(name);
    visited.add(name);
  };

  for (const relation of relations) {
    visit(relation.parent);
  }
}

function compareItems(left: IamPolicyItemInput, right: IamPolicyItemInput): number {
  return left.name.localeCompare(right.name) || left.type.localeCompare(right.type);
}

function compareRelations(left: IamPolicyRelationInput, right: IamPolicyRelationInput): number {
  return left.parent.localeCompare(right.parent) || left.child.localeCompare(right.child);
}
