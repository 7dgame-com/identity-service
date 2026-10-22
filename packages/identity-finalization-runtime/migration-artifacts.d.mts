declare const reservationBrand: unique symbol;
declare const ownedBrand: unique symbol;
export type MigrationJournalLease = { readonly [reservationBrand]: true };
export type OwnedMigrationJournal = { readonly [ownedBrand]: true };
export interface MigrationArtifactSession {
  readonly planSha256: string;
  readonly plan: {
    compiledRevision: string; imageDigest: string; executor: { id: string; bootId: string };
    target: { host: string; port: number; database: string; principal: string; fenceId: number };
    window: { startedAt: string; deadline: string };
    inputs: { sourceSnapshotSha256: string; profileSelectionSha256: string | null; allocatorReviewSha256: string };
    limits: { maxChanges: number; maxRows: number };
    steps: readonly { id: string; entry: string; mode: string; entrySha256: string }[];
  };
  readPreparedInputs(): Promise<Readonly<{ source: Buffer; review: Buffer; profile?: Buffer }>>;
  readStep(claim: unknown): Promise<Readonly<Record<string, Buffer>>>;
  reserveJournal(claim: unknown): Promise<MigrationJournalLease>;
  writeTypedOutput(claim: unknown, nativeBytes: Buffer, nativeSummaryBytes?: Buffer | null): Promise<{ report: { output: unknown; [key: string]: unknown }; reportSha256: string; outputSha256: string }>;
  close(): Promise<void>;
}
export const migrationArtifactLayout: Readonly<{ code: string; inputs: string; reports: string; revision: string; plan: string; source: string; profile: string; review: string }>;
export const migrationArtifactBounds: Readonly<{ plan: number; revision: number; entry: number; source: number; profile: number; review: number; report: number }>;
export function openMigrationArtifacts(binding: { planSha256: string; compiledRevision: string; imageDigest: string }): Promise<MigrationArtifactSession>;
export function consumeMigrationJournalLease(lease: MigrationJournalLease, claim: unknown): OwnedMigrationJournal;
export function appendMigrationJournal(owner: OwnedMigrationJournal, bytes: Buffer): Promise<unknown>;
export function syncMigrationJournal(owner: OwnedMigrationJournal): Promise<unknown>;
export function closeMigrationJournal(owner: OwnedMigrationJournal): Promise<void>;

export function validateMigrationTypedReport(claim: unknown, bytes: Buffer): { report: { output: unknown; [key: string]: unknown }; reportSha256: string; outputSha256: string };
