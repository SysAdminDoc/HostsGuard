using Xunit;

// The service tests share SQLite (shared-cache) and named-pipe resources whose
// teardown (SqliteConnection.ClearAllPools, pipe ACLs) is process-global, so
// running collections in parallel occasionally cross-trips an unrelated test.
// Serialize this assembly for determinism — the suite is fast enough (~5s).
[assembly: CollectionBehavior(DisableTestParallelization = true)]
