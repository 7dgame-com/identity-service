import { assertAdmissionWriter } from "./identity-admission.js";
import type { PoolConnection } from "mysql2/promise";

/** Hold the clock lock until commit, so a cursor cannot skip an earlier uncommitted ID. */
export async function enqueueSubjectEvent(connection: PoolConnection, userId: number): Promise<void> {
  assertAdmissionWriter();
  await connection.execute("SELECT id FROM identity_event_clock WHERE id = 1 FOR UPDATE");
  await connection.execute("INSERT INTO identity_subject_events (user_id,version) VALUES (?,?)", [userId, Date.now()]);
}
