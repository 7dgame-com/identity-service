export const legacyProfileArchiveColumns = ["id","user_id","payload_json","selected_profile_id","is_present"];

// Explicit identity-only columns. Business balances and file references never cross this boundary.
export const accountImportTables: Readonly<Record<string, readonly string[]>> = {
  user: ["id", "username", "auth_key", "password_hash", "password_reset_token", "verification_token", "email", "status", "nickname", "wx_openid", "email_verified_at", "created_at", "updated_at"],
  user_info: ["id", "user_id", "info"],
  auth_rule: ["name", "data", "created_at", "updated_at"],
  auth_item: ["name", "type", "description", "rule_name", "data", "created_at", "updated_at"],
  auth_item_child: ["parent", "child"],
  auth_assignment: ["item_name", "user_id", "created_at"],
  organization: ["id", "name", "title", "created_at", "updated_at"],
  user_organization: ["user_id", "organization_id"],
  wechat: ["id", "openid", "unionid", "user_id", "token", "created_at", "updated_at"],
  invitation_record: ["id", "invite_code", "inviter_id", "invitee_id", "created_at"],
  invitation: ["id", "code", "sender_id", "recipient_id", "used", "auth_item_name", "create_at"]
};
